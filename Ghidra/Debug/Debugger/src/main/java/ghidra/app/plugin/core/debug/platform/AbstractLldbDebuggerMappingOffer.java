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
package ghidra.app.plugin.core.debug.platform;

import java.util.Collection;

import ghidra.app.plugin.core.debug.mapping.AbstractDebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.lang.*;

public class AbstractLldbDebuggerMappingOffer extends AbstractDebuggerMappingOffer {
	public AbstractLldbDebuggerMappingOffer(TargetObject target, int confidence,
			String description, LanguageID langID, CompilerSpecID csID,
			Collection<String> extraRegNames) {
		super(target, confidence, description, langID, csID, extraRegNames);
	}

	@Override
	public DebuggerTargetTraceMapper take() {
		try {
			return new LldbTargetTraceMapper(target, langID, csID, extraRegNames);
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
			throw new AssertionError(e);
		}
	}
}
