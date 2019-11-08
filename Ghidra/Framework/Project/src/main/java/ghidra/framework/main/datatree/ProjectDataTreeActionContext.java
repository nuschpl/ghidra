/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.framework.main.datatree;

import java.util.List;

import javax.swing.tree.TreePath;

import docking.ComponentProvider;
import ghidra.framework.main.DomainFileOperationTracker;
import ghidra.framework.main.datatable.ProjectDataActionContext;
import ghidra.framework.model.*;

public class ProjectDataTreeActionContext extends ProjectDataActionContext {

	private TreePath[] selectionPaths;
	private DataTree tree;

	public ProjectDataTreeActionContext(ComponentProvider provider, ProjectData projectData,
			DomainFileOperationTracker fileTracker, TreePath[] selectionPaths,
			List<DomainFolder> folderList, List<DomainFile> fileList, DataTree tree,
			boolean isActiveProject) {
		super(provider, projectData, fileTracker, getContextObject(selectionPaths), folderList,
			fileList, tree, isActiveProject);
		this.selectionPaths = selectionPaths;
		this.tree = tree;
	}

	private static Object getContextObject(TreePath[] selectionPaths) {
		if (selectionPaths.length == 0) {
			return null;
		}
		return selectionPaths[0].getLastPathComponent();
	}

	public TreePath[] getSelectionPaths() {
		return selectionPaths;
	}

	public DataTree getTree() {
		return tree;
	}
}
