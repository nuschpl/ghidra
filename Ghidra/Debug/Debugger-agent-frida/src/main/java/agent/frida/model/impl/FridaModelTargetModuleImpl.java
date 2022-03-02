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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaModule;
import agent.frida.manager.FridaSession;
import agent.frida.model.iface2.FridaModelTargetModule;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "Module",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Sections",
			type = FridaModelTargetModuleSectionContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Symbols",
			type = FridaModelTargetSymbolContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Imports",
			type = FridaModelTargetImportContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Exports",
			type = FridaModelTargetExportContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "ImageName", type = String.class),
		//@TargetAttributeType(name = "UUID", type = String.class),
		@TargetAttributeType(name = "Len", type = String.class),
		@TargetAttributeType(type = Void.class)
	})
public class FridaModelTargetModuleImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetModule {

	protected static String indexModule(FridaModule module) {
		return FridaClient.getId(module);
	}

	protected static String keyModule(FridaModule module) {
		return PathUtils.makeKey(indexModule(module));
	}

	protected final FridaSession session;

	protected final FridaModelTargetSymbolContainerImpl symbols;
	protected final FridaModelTargetImportContainerImpl imports;
	protected final FridaModelTargetExportContainerImpl exports;
	protected final FridaModelTargetModuleSectionContainerImpl sections;

	public FridaModelTargetModuleImpl(FridaModelTargetModuleContainerImpl modules, FridaModule module) {
		super(modules.getModel(), modules, keyModule(module), module, "Module");
		this.session = modules.session;

		this.symbols = new FridaModelTargetSymbolContainerImpl(this);
		this.imports = new FridaModelTargetImportContainerImpl(this);
		this.exports = new FridaModelTargetExportContainerImpl(this);
		this.sections = new FridaModelTargetModuleSectionContainerImpl(this);

		AddressSpace space = getModel().getAddressSpace("ram");
		Address address;
		changeAttributes(List.of(), List.of( //
			sections, //
			symbols, //
			imports, //
			exports //
		), Map.of( //
			//DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, module.getName(), //
			MODULE_NAME_ATTRIBUTE_NAME, module.getPath(), //
			"ImageName", module.getPath() //
			//"UUID", module.GetUUIDString() //
		), "Initialized");
		
		try {
			address = space.getAddress(module.getRangeAddress());
			AddressRangeImpl range = new AddressRangeImpl(address, module.getRangeSize());
			changeAttributes(List.of(), List.of(), Map.of( //
				RANGE_ATTRIBUTE_NAME, range, //
				"BaseAddress", address, //
				"Len", Long.toHexString(module.getRangeSize()) //
			), "Initialized");
		} catch (AddressFormatException | AddressOverflowException e) {
			// Nothing
		}

	}

	public String getDescription(int level) {
		FridaModule module = (FridaModule) getModelObject();
		return module.getName();
	}

	protected Address doGetBase() {
		return null; //getModel().getAddressSpace("ram").getAddress(module.getKnownBase());
	}

	@Override
	public FridaModule getModule() {
		return (FridaModule) getModelObject();
	}

	public FridaSession getSession() {
		return session;
	}

	@Override
	public void setRange(AddressRangeImpl range) {
		if (range != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
					RANGE_ATTRIBUTE_NAME, range, //
					"BaseAddress", range.getMinAddress(), //
					"Len", Long.toHexString(range.getLength()) //
			), "Initialized");
		}
	}

}
