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
package ghidra.app.util.viewer.field;

import java.awt.event.MouseEvent;
import java.util.*;

import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.field.TextField;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.*;
import ghidra.util.table.ReferencesFromTableModel;
import util.CollectionUtils;

/**
 * A handler to process {@link XRefFieldMouseHandler} clicks.
 */
public class XRefFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES =
		new Class<?>[] { XRefFieldLocation.class, XRefHeaderFieldLocation.class };

	/**
	 * @see FieldMouseHandlerExtension#fieldElementClicked(Object, Navigatable, MouseEvent, ServiceProvider)
	 */
	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}

		// If I double-click on the XRef Header, show references to this place, also works on 
		// 'more' field. This is much nicer if you have multiple references to navigate.
		if (isXREFHeaderLocation(location)) {
			showXRefDialog(sourceNavigatable, location, serviceProvider);
			return true;
		}

		Address referencedAddress = getFromReferenceAddress(location);
		String clickedText = getText(clickedObject);
		boolean isInvisibleXRef = XRefFieldFactory.MORE_XREFS_STRING.equals(clickedText);
		if (isInvisibleXRef) {
			showXRefDialog(sourceNavigatable, location, serviceProvider);
			return true;
		}

		return goTo(sourceNavigatable, referencedAddress, goToService);
	}

	protected boolean isXREFHeaderLocation(ProgramLocation location) {
		return location instanceof XRefHeaderFieldLocation;
	}

	private String getText(Object clickedObject) {
		if (clickedObject instanceof TextField) {
			TextField textField = (TextField) clickedObject;
			return textField.getText();
		}
		else if (clickedObject instanceof FieldElement) {
			FieldElement fieldElement = (FieldElement) clickedObject;
			return fieldElement.getText();
		}
		return clickedObject.toString();
	}

	// the unused parameter is needed for overridden method in subclass
	protected Address getToReferenceAddress(ProgramLocation programLocation, Program program) {
		return programLocation.getAddress();
	}

	protected Address getFromReferenceAddress(ProgramLocation programLocation) {
		return ((XRefFieldLocation) programLocation).getRefAddress();
	}

	protected int getIndex(ProgramLocation programLocation) {
		return ((XRefFieldLocation) programLocation).getIndex();
	}

	protected void showXRefDialog(Navigatable navigatable, ProgramLocation location,
			ServiceProvider serviceProvider) {
		TableService service = serviceProvider.getService(TableService.class);
		if (service == null) {
			return;
		}

		Address toAddress = location.getAddress();
		Program program = navigatable.getProgram();

		CodeUnit cu = getImmediateDataContaining(location, program);
		if (cu == null) {
			Listing listing = program.getListing();
			cu = listing.getCodeUnitContaining(toAddress);
		}

		List<Reference> refs = getReferences(cu);
		showReferenceTable(navigatable, serviceProvider, service, toAddress, program, refs);
	}

	protected void showReferenceTable(Navigatable navigatable, ServiceProvider serviceProvider,
			TableService service, Address toAddress, Program program, List<Reference> refs) {
		ReferencesFromTableModel model =
			new ReferencesFromTableModel(refs, serviceProvider, program);
		service.showTable("XRefs to " + toAddress.toString(), "XRefs", model, "XRefs", navigatable);
	}

	private List<Reference> getReferences(CodeUnit cu) {
		Reference[] xrefs = XReferenceUtil.getXReferences(cu, XReferenceUtil.ALL_REFS);
		Reference[] offcuts = XReferenceUtil.getOffcutXReferences(cu, XReferenceUtil.ALL_REFS);

		// Convert to a set before combining lists, to remove duplicates.
		Set<Reference> set = CollectionUtils.asSet(xrefs);
		set.addAll(Arrays.asList(offcuts));

		return new ArrayList<>(set);
	}

	/**
	 * Returns the nearest {@link Data} object containing a given address.
	 * 
	 * @param location the program location within the data object
	 * @param program the current program
	 * @return the Data object
	 */
	private Data getImmediateDataContaining(ProgramLocation location, Program program) {
		Address addr = location.getAddress();
		Listing listing = program.getListing();
		Data dataContaining = listing.getDataContaining(addr);
		if (dataContaining == null) {
			return null;
		}

		Data dataAtAddr = dataContaining.getComponent(location.getComponentPath());
		return dataAtAddr;
	}

	protected ProgramLocation getReferredToLocation(Navigatable sourceNavigatable,
			ProgramLocation location) {
		Program program = sourceNavigatable.getProgram();
		return new CodeUnitLocation(program, getToReferenceAddress(location, program), 0, 0, 0);
	}

	private boolean goTo(Navigatable navigatable, Address referencedAddress,
			GoToService goToService) {
		if (referencedAddress != null) {
			return goToService.goTo(navigatable, referencedAddress);
		}
		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
