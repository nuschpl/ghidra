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
package ghidra.app.plugin.core.osgi;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.osgi.framework.*;
import org.osgi.framework.wiring.BundleRequirement;

public class OSGiUtils {

	/**
	 * The syntax of the error generated when OSGi requirements cannot be resolved is
	 * difficult to parse, so we try to extract package names.
	 * 
	 * @param osgiExceptionMessage the exception message
	 * @return a list of package names
	 */
	static List<String> extractPackageNamesFromFailedResolution(String osgiExceptionMessage) {
		try (Scanner s = new Scanner(osgiExceptionMessage)) {
			return s.findAll(Pattern.compile("\\(osgi\\.wiring\\.package=([^)]*)\\)")).map(m -> {
				return m.group(1);
			}).collect(Collectors.toList());
		}
	}

	static String getEventTypeString(BundleEvent e) {
		switch (e.getType()) {
			case BundleEvent.INSTALLED:
				return "INSTALLED";
			case BundleEvent.RESOLVED:
				return "RESOLVED";
			case BundleEvent.LAZY_ACTIVATION:
				return "LAZY_ACTIVATION";
			case BundleEvent.STARTING:
				return "STARTING";
			case BundleEvent.STARTED:
				return "STARTED";
			case BundleEvent.STOPPING:
				return "STOPPING";
			case BundleEvent.STOPPED:
				return "STOPPED";
			case BundleEvent.UPDATED:
				return "UPDATED";
			case BundleEvent.UNRESOLVED:
				return "UNRESOLVED";
			case BundleEvent.UNINSTALLED:
				return "UNINSTALLED";
			default:
				return "???";
		}
	}

	/**
	 * parse Import-Package string from a bundle manifest
	 * 
	 * @param imports Import-Package value
	 * @return deduced requirements or null if there was an error
	 * @throws BundleException on parse failure
	 */
	static List<BundleRequirement> parseImports(String imports) throws BundleException {
		// parse it with Felix's ManifestParser to a list of BundleRequirement objects
		Map<String, Object> headerMap = new HashMap<>();
		headerMap.put(Constants.IMPORT_PACKAGE, imports);
		ManifestParser mp;
		mp = new ManifestParser(null, null, null, headerMap);
		return mp.getRequirements();
	}

	// from https://dzone.com/articles/locate-jar-classpath-given
	static String findJarForClass(Class<?> c) {
		final URL location;
		final String classLocation = c.getName().replace('.', '/') + ".class";
		final ClassLoader loader = c.getClassLoader();
		if (loader == null) {
			location = ClassLoader.getSystemResource(classLocation);
		}
		else {
			location = loader.getResource(classLocation);
		}
		if (location != null) {
			Pattern p = Pattern.compile("^.*:(.*)!.*$");
			Matcher m = p.matcher(location.toString());
			if (m.find()) {
				return m.group(1);
			}
			return null; // not loaded from jar?
		}
		return null;
	}

	static void getPackagesFromClasspath(Set<String> s) {
		getClasspathElements().forEach(p -> {
			if (Files.isDirectory(p)) {
				collectPackagesFromDirectory(p, s);
			}
			else if (p.toString().endsWith(".jar")) {
				collectPackagesFromJar(p, s);
			}
		});
	}

	static Stream<Path> getClasspathElements() {
		String classpathStr = System.getProperty("java.class.path");
		return Collections.list(new StringTokenizer(classpathStr, File.pathSeparator))
			.stream()
			.map(String.class::cast)
			.map(Paths::get)
			.map(Path::normalize);
	}

	static void collectPackagesFromDirectory(Path dirPath, Set<String> s) {
		try {
			Files.walk(dirPath).filter(p -> p.toString().endsWith(".class")).forEach(p -> {
				String n = dirPath.relativize(p).toString();
				int lastSlash = n.lastIndexOf(File.separatorChar);
				s.add(lastSlash > 0 ? n.substring(0, lastSlash).replace(File.separatorChar, '.')
						: "");
			});

		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	static void collectPackagesFromJar(Path jarPath, Set<String> s) {
		try {
			try (JarFile j = new JarFile(jarPath.toFile())) {
				j.stream().filter(je -> je.getName().endsWith(".class")).forEach(je -> {
					String n = je.getName();
					int lastSlash = n.lastIndexOf('/');
					s.add(lastSlash > 0 ? n.substring(0, lastSlash).replace('/', '.') : "");
				});
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}
