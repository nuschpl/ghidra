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
package ghidra.dbg.sctl.protocol.common;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.fields.PacketField;

public class SctlRegisterDefinition extends Packet {
	public SctlRegisterDefinition() {
	}

	public SctlRegisterDefinition(long regid, String name, long nbits) {
		this.regid = regid;
		this.name = new SctlString(name);
		this.nbits = nbits;
	}

	@PacketField
	public long regid;

	@PacketField
	public SctlString name;

	// TODO: Consider a type name instead/in addition?
	@PacketField
	public long nbits;
}
