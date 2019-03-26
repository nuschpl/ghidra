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
/* Generated by Together */

package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

/**
 * <CODE>FunctionLocation</CODE> provides information about the location
 * in a program within a <CODE>Function</CODE>.
 */
public class FunctionLocation extends ProgramLocation {
	protected Address functionAddr;

	/**
	 * Create a new FunctionLocation.
	 *
	 * @param the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param row the row in the field
	 * @param col the display piece on the row
	 * @param charOffset the character position within the display piece specifed by row,col
	 */
	protected FunctionLocation(Program program, Address locationAddr, Address functionAddr, int row,
			int col, int charOffset) {
		super(program, locationAddr, row, col, charOffset);
		this.functionAddr = functionAddr;
	}

	/**
	 * Default constructor needed for restoring
	 * a program function location from XML
	 */
	protected FunctionLocation() {
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (super.equals(obj)) {
			FunctionLocation loc = (FunctionLocation) obj;
			return compareAddr(functionAddr, loc.functionAddr) == 0;
		}
		return false;
	}

	/**
	 * Return the Function symbol address which may differ from the "location address" when
	 * a function is indirectly inferred via a reference.  WARNING: The {@link #getAddress()} should
	 * not be used to obtain the function address!
	 * @return the function address corresponding to this program location
	 */
	public Address getFunctionAddress() {
		return functionAddr;
	}

	/**
	 * Save this function location to the given save state object.
	 *
	 * @param obj the save state object for saving the location
	 * @param prefix prefix appended to the names of the save state items to make the entry unique
	 */
	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);

		if (functionAddr != null) { // should never be null, but don't explode			
			obj.putString("_FUNC_ADDRESS", functionAddr.toString());
		}
	}

	/**
	 * Restore this function location using the given program and save state object.
	 *
	 * @param prefix prefix appended to the names of the save state items to make the entry unique
	 */
	@Override
	public void restoreState(Program program1, SaveState obj) {
		super.restoreState(program1, obj);
		String addrStr = obj.getString("_FUNC_ADDRESS", null);
		functionAddr = getAddress(program1, addrStr);
	}

	private Address getAddress(Program program1, String addressString) {
		if (addressString == null) {
			return addr;
		}

		Address newAddress = ProgramUtilities.parseAddress(program1, addressString);
		return newAddress == null ? addr : newAddress;
	}

	@Override
	public boolean isValid(Program p) {
		if (!super.isValid(p)) {
			return false;
		}

		Listing listing = p.getListing();
		if (!addr.equals(functionAddr)) {
			// ensure that inferred function reference is valid
			if (listing.getFunctionAt(addr) != null) {
				return false;
			}
			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (!(cu instanceof Data)) {
				return false;
			}
			Data data = (Data) cu;
			if (!(data.getDataType() instanceof Pointer)) {
				return false;
			}
			Reference ref = data.getPrimaryReference(0);
			if (ref == null || !ref.getToAddress().equals(functionAddr)) {
				return false;
			}
		}

		return listing.getFunctionAt(functionAddr) != null;

	}

	@Override
	public String toString() {
		if (addr.equals(functionAddr)) {
			return super.toString();
		}
		return super.toString() + " functionAddr=" + functionAddr;
	}
}
