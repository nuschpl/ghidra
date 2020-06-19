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
package ghidra.framework.main.datatable;

import docking.action.ContextSpecificAction;

public abstract class ProjectDataAction
		extends ContextSpecificAction<ProjectDataContext> {

	public ProjectDataAction(String name, String owner) {
		super(name, owner, ProjectDataContext.class);
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		return context.hasOneOrMoreFilesAndFolders();
	}

}
