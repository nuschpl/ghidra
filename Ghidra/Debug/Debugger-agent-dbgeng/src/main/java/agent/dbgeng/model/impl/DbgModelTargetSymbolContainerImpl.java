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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.manager.impl.DbgMinimalSymbol;
import agent.dbgeng.model.iface2.DbgModelTargetSymbolContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.util.datastruct.WeakValueHashMap;

public class DbgModelTargetSymbolContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSymbolContainer {

	protected final DbgModelTargetModuleImpl module;

	protected final Map<String, DbgModelTargetSymbolImpl> symbolsByName = new WeakValueHashMap<>();

	public DbgModelTargetSymbolContainerImpl(DbgModelTargetModuleImpl module) {
		super(module.getModel(), module, "Symbols", "SymbolContainer");
		this.module = module;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return module.module.listMinimalSymbols().thenAccept(byName -> {
			List<TargetObject> symbols;
			synchronized (this) {
				symbols = byName.values()
						.stream()
						.map(this::getTargetSymbol)
						.collect(Collectors.toList());
			}
			setElements(symbols, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized DbgModelTargetSymbolImpl getTargetSymbol(DbgMinimalSymbol symbol) {
		return symbolsByName.computeIfAbsent(symbol.getName(),
			n -> new DbgModelTargetSymbolImpl(this, symbol));
	}
}
