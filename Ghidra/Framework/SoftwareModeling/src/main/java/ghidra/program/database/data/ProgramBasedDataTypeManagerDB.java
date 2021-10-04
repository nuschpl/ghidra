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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.List;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.KeyRange;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * DB-based Program datatype manager implementation
 * which has the concept of an address-based listing and corresponding
 * datatype instance settings.
 */
public abstract class ProgramBasedDataTypeManagerDB extends DataTypeManagerDB
		implements ProgramBasedDataTypeManager {

	private static final String INSTANCE_SETTINGS_TABLE_NAME = "Instance Settings";

	private SettingsDBAdapter instanceSettingsAdapter;
	private SettingsCache<Address> instanceSettingsCache = new SettingsCache<>(200);

	/**
	 * Constructor
	 * @param handle open database  handle
	 * @param addrMap the address map (instance settings not supported if null)
	 * @param openMode the program open mode (see {@link DBConstants})
	 * @param errHandler the database io error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database IO error occurs.
	 */
	public ProgramBasedDataTypeManagerDB(DBHandle handle, AddressMap addrMap, int openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, addrMap, openMode, errHandler, lock, monitor);
	}

	protected void initializeOtherAdapters(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		if (addrMap != null) {
			instanceSettingsAdapter =
				SettingsDBAdapter.getAdapter(INSTANCE_SETTINGS_TABLE_NAME, dbHandle, openMode,
					addrMap, monitor);
		}
	}

	@Override
	public void invalidateCache() {
		lock.acquire();
		try {
			super.invalidateCache();
			if (instanceSettingsAdapter != null) {
				instanceSettingsAdapter.invalidateNameCache();
				instanceSettingsCache.clear();
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Provides notification when a data instance setting has changed at a specific address.
	 * @param address data address
	 */
	abstract protected void dataSettingChanged(Address address);

	@Override
	public boolean setLongSettingsValue(Address dataAddr, String name, long value) {
		return updateInstanceSettings(dataAddr, name, null, value);
	}

	@Override
	public boolean setStringSettingsValue(Address dataAddr, String name, String value) {
		return updateInstanceSettings(dataAddr, name, value, -1);
	}

	@Override
	public boolean setSettings(Address dataAddr, String name, Object value) {
		if (value instanceof String) {
			return updateInstanceSettings(dataAddr, name, (String) value, -1);
		}
		else if (isAllowedNumberType(value)) {
			return updateInstanceSettings(dataAddr, name, null, ((Number) value).longValue());
		}
		throw new IllegalArgumentException(
			"Unsupportd Settings Value: " + (value == null ? "null" : value.getClass().getName()));
	}

	private boolean isAllowedNumberType(Object value) {
		if (value instanceof Long) {
			return true;
		}
		if (value instanceof Integer) {
			return true;
		}
		if (value instanceof Short) {
			return true;
		}
		if (value instanceof Byte) {
			return true;
		}
		return false;
	}

	@Override
	public Long getLongSettingsValue(Address dataAddr, String name) {
		SettingDB settings = getSettingDB(dataAddr, name);
		if (settings != null) {
			return settings.getLongValue();
		}
		return null;
	}

	@Override
	public String getStringSettingsValue(Address dataAddr, String name) {
		SettingDB settings = getSettingDB(dataAddr, name);
		if (settings != null) {
			return settings.getStringValue();
		}
		return null;
	}

	@Override
	public Object getSettings(Address dataAddr, String name) {
		Object obj = getStringSettingsValue(dataAddr, name);
		if (obj != null) {
			return obj;
		}
		return getLongSettingsValue(dataAddr, name);
	}

	@Override
	public boolean clearSetting(Address dataAddr, String name) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			instanceSettingsCache.remove(dataAddr, name);
			long addr = addrMap.getKey(dataAddr, false);
			if (instanceSettingsAdapter.removeSettingsRecord(addr, name)) {
				dataSettingChanged(dataAddr);
				return true;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public void clearAllSettings(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			instanceSettingsCache.clear();
			boolean changed = false;
			Field[] keys = instanceSettingsAdapter.getSettingsKeys(addrMap.getKey(dataAddr, false));
			for (Field key : keys) {
				instanceSettingsAdapter.removeSettingsRecord(key.getLongValue());
				changed = true;
			}
			if (changed) {
				dataSettingChanged(dataAddr);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}

		DBHandle scratchPad = null;
		lock.acquire();
		try {
			instanceSettingsCache.clear();
			scratchPad = dbHandle.getScratchPad();
			Table tmpTable = scratchPad.createTable(INSTANCE_SETTINGS_TABLE_NAME,
				SettingsDBAdapterV1.V1_SETTINGS_SCHEMA);

			List<KeyRange> keyRanges =
				addrMap.getKeyRanges(fromAddr, fromAddr.add(length - 1), false);
			for (KeyRange range : keyRanges) {
				RecordIterator iter =
					instanceSettingsAdapter.getRecords(range.minKey, range.maxKey);
				while (iter.hasNext()) {
					monitor.checkCanceled();
					DBRecord rec = iter.next();
					tmpTable.putRecord(rec);
					iter.delete();
				}
			}

			RecordIterator iter = tmpTable.iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				// update address key (i.e., settings association ID) and re-introduce into table
				Address addr = addrMap
						.decodeAddress(
							rec.getLongValue(SettingsDBAdapter.SETTINGS_ASSOCIATION_ID_COL));
				long offset = addr.subtract(fromAddr);
				addr = toAddr.add(offset);
				rec.setLongValue(SettingsDBAdapter.SETTINGS_ASSOCIATION_ID_COL,
					addrMap.getKey(addr, true));
				instanceSettingsAdapter.updateSettingsRecord(rec);
			}

		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			if (scratchPad != null) {
				try {
					scratchPad.deleteTable(INSTANCE_SETTINGS_TABLE_NAME);
				}
				catch (IOException e) {
					// ignore
				}
			}
			lock.release();
		}
	}

	@Override
	public String[] getInstanceSettingsNames(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			return instanceSettingsAdapter.getSettingsNames(addrMap.getKey(dataAddr, false));
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return new String[0];
	}

	@Override
	public boolean isEmptySetting(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		try {
			return instanceSettingsAdapter
					.getSettingsKeys(addrMap.getKey(dataAddr, false)).length == 0;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return true;
	}

	private boolean updateInstanceSettings(Address dataAddr, String name, String strValue,
			long longValue) {

		boolean wasChanged = false;

		lock.acquire();
		try {
			if (instanceSettingsAdapter == null) {
				throw new UnsupportedOperationException();
			}
			long addrKey = addrMap.getKey(dataAddr, true);
			DBRecord rec =
				instanceSettingsAdapter.updateSettingsRecord(addrKey, name, strValue, longValue);
			if (rec != null) {
				SettingDB setting = new SettingDB(rec, instanceSettingsAdapter.getSettingName(rec));
				instanceSettingsCache.put(dataAddr, name, setting);
				dataSettingChanged(dataAddr);
				return true;
			}
			return false;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}

		return wasChanged;
	}

	private SettingDB getSettingDB(Address dataAddr, String name) {
		lock.acquire();
		try {
			if (instanceSettingsAdapter == null) {
				throw new UnsupportedOperationException();
			}
			SettingDB settings = instanceSettingsCache.get(dataAddr, name);
			if (settings != null) {
				return settings;
			}
			long addr = addrMap.getKey(dataAddr, false);
			DBRecord rec = instanceSettingsAdapter.getSettingsRecord(addr, name);
			if (rec != null) {
				settings = new SettingDB(rec, instanceSettingsAdapter.getSettingName(rec));
				instanceSettingsCache.put(dataAddr, name, settings);
				return settings;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			List<?> addrKeyRanges = addrMap.getKeyRanges(startAddr, endAddr, false);
			int cnt = addrKeyRanges.size();
			for (int i = 0; i < cnt; i++) {
				KeyRange kr = (KeyRange) addrKeyRanges.get(i);
				instanceSettingsAdapter.delete(kr.minKey, kr.maxKey, monitor);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			instanceSettingsCache.clear();
			lock.release();
		}
	}
}
