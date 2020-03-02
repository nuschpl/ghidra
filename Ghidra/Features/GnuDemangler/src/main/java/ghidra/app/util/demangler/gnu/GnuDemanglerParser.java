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
package ghidra.app.util.demangler.gnu;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.demangler.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.StringUtilities;

public class GnuDemanglerParser {

	private static final String CONSTRUCTION_VTABLE_FOR = "construction vtable for ";
	private static final String VTT_FOR = "VTT for ";
	private static final String VTABLE_FOR = "vtable for ";
	private static final String TYPEINFO_NAME_FOR = "typeinfo name for ";
	private static final String TYPEINFO_FN_FOR = "typeinfo fn for ";
	private static final String TYPEINFO_FOR = "typeinfo for ";
	private static final String COVARIANT_RETURN_THUNK = "covariant return thunk";

	private static final Set<String> ADDRESS_TABLE_PREFIXES = Set.of(
		CONSTRUCTION_VTABLE_FOR,
		VTT_FOR,
		VTABLE_FOR,
		TYPEINFO_FN_FOR,
		TYPEINFO_FOR);

	private static final String NAMESPACE_DELIMITER = "::";

	/**
	 * <pre>
	 * Syntax: bob((Rect &, unsigned long))
	 *
	 * pattern: optional spaces followed by '()' with a capture group for the contents of the
	 *          parens
	 * note:    this pattern is used for matching the arguments string, in the above example it
	 *          would be: (Rect &, unsigned long)
	 *          
	 * Also matches: bob(const(Rect &, bool))
	 * </pre>
	 */
	private static final Pattern UNNECESSARY_PARENS_PATTERN =
		Pattern.compile("\\s*(const){0,1}\\((.*)\\)\\s*");

	/**
	 * <pre>
	 * Syntax: 	bob(short (&)[7])
	 * 			bob(int const[8] (*) [12])
	 *
	 * 			   typename[optional '*']<space>(*|&)[optional spaces][optional value]
	 *
	 * pattern:
	 * 				-a word
	 * 				-followed by a space
	 * 				-*optional: any other text (e.g., const[8])
	 * 				-followed by '()' that contain a '&' or a '*'
	 * 				-followed by one or more '[]' with optional interior text
	 * </pre>
	 */
	private static final Pattern ARRAY_POINTER_REFERENCE_PATTERN =
		Pattern.compile("([\\w:]+)\\*?\\s(.*)\\(([&*])\\)\\s*((?:\\[.*?\\])+)");

	/**
	 * <pre>
	 * Syntax: bob(short (&)[7])
	 *
	 * 			   (*|&)[optional spaces][optional value]
	 *
	 * pattern: '()' that contain a '&' or a '*' followed by '[]' with optional text; a capture
	 *          group for the contents of the parens
	 * </pre>
	*/
	private static final Pattern ARRAY_POINTER_REFERENCE_PIECE_PATTERN =
		Pattern.compile("\\(([&*])\\)\\s*\\[.*?\\]");

	/**
	* <pre>
	* Syntax: (unsigned)4294967295
	*
	* 			   (some text)[optional space]1 or more characters
	*
	* Regex:
	*
	* pattern:
	* 			-parens containing text
	* 			--the text can have "::" namespace separators (this is in a non-capturing group) and
	*             must be followed by more text
	*           --the text can have multiple words, such as (unsigned long)
	*           -optional space
	*           -optional '-' character (a negative sign character)
	* 			-followed by more text (with optional spaces)
	* </pre>
	*/
	private static final Pattern CAST_PATTERN =
		Pattern.compile("\\((?:\\w+\\s)*\\w+(?:::\\w+)*\\)\\s*-{0,1}\\w+");

	private static final String OPERATOR = "operator";

	/**
	 * <pre>
	 * Syntax: 
	 *         Magick::operator<(Magick::Coordinate const&, Magick::Coordinate const&)
	 * 		   std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char> >(std::basic_istream<char, std::char_traits<char> >&, char&)
	 * 
	 * 		  [return_type] operator opeartor_character(s) (opeartor_params)
	 *
	 * Regex:
	 * 
	 * pattern:
	 * 			-maybe a return type
	 * 			-operator
	 * 			-operator character(s)
	 *          -parameters
	 * </pre>
	 * 
	 * 
	 */
	private static final Pattern OVERLOAD_OPERATOR_PATTERN =
		createOverloadedOperatorPattern();

	/**
	* <pre>
	* Syntax: std::integral_constant<bool, false>::operator bool() const
	*         Magick::Color::operator std::basic_string<char, std::char_traits<char>, std::allocator<char> >() const
	*         
	* pattern:
	* 			-operator
	* 			-space
	*           -keyword for cast type
	*           -optional keywords
	*
	* </pre>
	*/
	private static final Pattern CONVERSION_OPERATOR_PATTERN =
		Pattern.compile("(.*" + OPERATOR + ") (.*)\\(\\).*");

	/**
	* <pre>
	* Syntax: operator new(unsigned long)
	*         operator new(void*)
	*         operator new[](void*)
	*
	* pattern:
	* 			-operator
	* 			-space
	*           -keyword 'new' or 'delete'
	*           -optional array brackets
	*           -optional parameters
	*
	* </pre>
	*/
	private static final Pattern NEW_DELETE_OPERATOR_PATTERN =
		Pattern.compile("(.*" + OPERATOR + ") (new|delete)(\\[\\])?\\((.*)\\).*");

	private static final String LAMBDA = "lambda";

	/**
	 * Pattern for newer C++ lambda syntax:
	 * 
	 * <pre>
	 *  {lambda(void const*, unsigned int)#1}
	 * 
	 *  1 - full text
	 *  2 - params
	 *  3 - trailing id
	 *  </pre>
	 */
	private static final Pattern LAMBDA_PATTERN =
		Pattern.compile(".*(\\{" + LAMBDA + "\\((.*)\\)(#\\d+)\\})");

	/**
	 * The c 'decltype' keyword pattern  
	 */
	private static final Pattern DECLTYPE_RETURN_TYPE_PATTERN =
		Pattern.compile("decltype \\(.*\\)");

	// note: the '?' after the .*   this is there to allow the trailing digits to match as many as
	// possible
	private static final Pattern ENDS_WITH_DIGITS_PATTERN = Pattern.compile("(.*?)\\d+");

	/**
	 * Examples:
	 *		construction vtable for
	 *		vtable for
	 *		typeinfo name for
	 *		typeinfo for
	 *		guard variable for
	 *		covariant return thunk to
	 *		virtual thunk to 
	 *		non-virtual thunk to
	 */
	private static final Pattern DESCRIPTIVE_PREFIX_PATTERN =
		Pattern.compile("((.+ )+(for|to) )(.*)");

	private static final char NULL_CHAR = '\u0000';
	private static final String VAR_ARGS = "...";
	private static final String THUNK = "thunk";
	private static final String CONST_KEYWORD = " const";

	private static Pattern createOverloadedOperatorPattern() {

		//@formatter:off
		Set<String> operators = new HashSet<>(Set.of(
			"++", "--",
			"+", "-", "*", "/", "%",
			"==", "!=", ">", "<", ">=", "<=",
			"&", "|", ">>", "<<", "~", "^",
			"&&", "||", "!",
			"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ">>=", "<<=",
			",", "()"
		));
		//@formatter:on

		CollectionUtils.transform(operators, Pattern::quote);
		String alternated = StringUtils.join(operators, "|");
		return Pattern.compile("(.*" + OPERATOR + "(" + alternated + ").*)\\s*(\\(.*\\))(.*)");

	}

	/**
	 * Parses the given demangled string and creates a {@link DemangledObject}
	 * 
	 * @param mangled the original mangled text
	 * @param demangled the demangled text
	 * @return the demangled object
	 * @throws DemanglerParseException if there is an unexpected error parsing
	 */
	public DemangledObject parse(String mangled, String demangled)
			throws DemanglerParseException {

		OperatorHandler operatorHandler = getOperatorHandler(demangled);
		if (operatorHandler != null) {
			DemangledObject dobj = operatorHandler.build();
			dobj.setMangledString(mangled);
			dobj.setOriginalDemangled(demangled);
			return dobj;
		}

		SpecialPrefixHandler handler = getSpecialPrefixHandler(mangled, demangled);
		if (handler != null) {
			String type = handler.getType();
			DemangledObject dobj = doParse(type);
			DemangledObject specialPrefixDobj = handler.build(dobj);
			specialPrefixDobj.setMangledString(mangled);
			specialPrefixDobj.setOriginalDemangled(demangled);
			return specialPrefixDobj;
		}

		DemangledObject dobj = doParse(demangled);
		dobj.setMangledString(mangled);
		dobj.setOriginalDemangled(demangled);

		return dobj;
	}

	private OperatorHandler getOperatorHandler(String demangled) {

		OperatorHandler handler = new OverloadOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		handler = new ConversionOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		handler = new NewOrDeleteOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		return null;
	}

	private SpecialPrefixHandler getSpecialPrefixHandler(String mangled, String demangled) {

		Matcher matcher = DESCRIPTIVE_PREFIX_PATTERN.matcher(demangled);
		if (matcher.matches()) {
			String prefix = matcher.group(1);
			String type = matcher.group(4);
			if (prefix.contains(THUNK)) {
				return new ThunkHandler(demangled, prefix, type);
			}

			if (ADDRESS_TABLE_PREFIXES.contains(prefix)) {
				return new AddressTableHandler(demangled, prefix, type);
			}

			if (prefix.startsWith(TYPEINFO_NAME_FOR)) {
				return new TypeInfoNameHandler(demangled, TYPEINFO_NAME_FOR);
			}

			return new ItemInNamespaceHandler(demangled, prefix, type);
		}

		if (mangled.startsWith("_ZZ")) {
			return new ItemInNamespaceHandler(demangled);
		}
		return null;
	}

	private DemangledObject doParse(String demangled) {

		ParameterLocator paramLocator = new ParameterLocator(demangled);
		if (!paramLocator.hasParameters()) {
			return parseVariable(demangled);
		}

		int paramStart = paramLocator.getParamStart();
		int paramEnd = paramLocator.getParamEnd();

		String parameterString = demangled.substring(paramStart + 1, paramEnd).trim();
		List<DemangledDataType> parameters = parseParameters(parameterString);

		// 'prefix' is the text before the parameters
		int prefixEndPos = paramStart;
		String prefix = demangled.substring(0, prefixEndPos).trim();
		prefix = fixupInternalSeparators(prefix);

		int nameStart = Math.max(0, prefix.lastIndexOf(' '));
		String name = prefix.substring(nameStart, prefix.length()).trim();
		DemangledFunction function = new DemangledFunction(null);
		String simpleName = name;
		LambdaName lambdaName = getLambdaName(demangled);
		if (lambdaName != null) {
			String uniqueName = lambdaName.getFullText();
			String fullLambda = fixupInternalSeparators(uniqueName);
			simpleName = name.replace("{lambda", fullLambda);
			function = new DemangledLambda(null);
			function.setSignature(lambdaName.getFullText());
		}

		// For GNU, we cannot leave the return type as null, because the DemangleCmd will fill in
		// pointer to the class to accommodate windows demangling
		function.setReturnType(new DemangledDataType("undefined"));
		for (DemangledDataType parameter : parameters) {
			function.addParameter(parameter);
		}

		setNameAndNamespace(function, simpleName);

		// check for return type
		if (nameStart > 0) {
			String returnType = prefix.substring(0, nameStart);
			setReturnType(function, returnType);
		}

		if (demangled.endsWith(CONST_KEYWORD)) {
			function.setConst(true);
		}

		return function;
	}

	private void setReturnType(DemangledFunction function, String returnType) {

		if (DECLTYPE_RETURN_TYPE_PATTERN.matcher(returnType).matches()) {
			// Not sure yet if there is any information we wish to recover from this pattern.
			// Sample: decltype (functionName({parm#1}, (float)[42c80000])) 
			return;
		}

		function.setReturnType(parseDataType(returnType));
	}

	private LambdaName getLambdaName(String name) {
		Matcher matcher = LAMBDA_PATTERN.matcher(name);
		if (!matcher.matches()) {
			return null;
		}

		String fullText = matcher.group(1);
		String params = matcher.group(2);
		String trailing = matcher.group(3);
		return new LambdaName(fullText, params, trailing);
	}

	private String stripOffTemplates(String string) {
		StringBuilder buffy = new StringBuilder();
		int depth = 0;
		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			if (c == '<') {
				depth++;
				continue;
			}
			else if (c == '>') {
				depth--;
				continue;
			}

			if (depth == 0) {
				buffy.append(c);
			}
		}
		return buffy.toString();
	}

	private DemangledObject parseItemInNamespace(String itemText) {

		int pos = itemText.lastIndexOf(NAMESPACE_DELIMITER);
		if (pos == -1) {
			throw new DemanglerParseException(
				"Expected the demangled string to contain a namespace");
		}

		String parentText = itemText.substring(0, pos);
		DemangledObject parent = doParse(parentText);
		String name = itemText.substring(pos + 2);
		DemangledObject item = doParse(name);
		item.setNamespace(parent);
		return item;
	}

	/**
	 * Replaces all SPACES and COLONS inside of groups (templates/parentheses) 
	 * with UNDERSCORES and DASHES, respectively
	 */
	private String fixupInternalSeparators(String name) {
		StringBuilder buffer = new StringBuilder();
		int depth = 0;
		char last = NULL_CHAR;
		for (int i = 0; i < name.length(); ++i) {
			char ch = name.charAt(i);
			if (ch == '<' || ch == '(') {
				++depth;
			}
			else if ((ch == '>' || ch == ')') && depth != 0) {
				--depth;
			}

			if (depth > 0 && ch == ' ') {
				char next = (i + 1) < name.length() ? name.charAt(i + 1) : NULL_CHAR;
				if (isSurroundedByCharacters(last, next)) {
					// separate words with a value so they don't run together; drop the other spaces
					buffer.append('_');
				}
			}
			else if (depth > 0 && ch == ':') {
				buffer.append('-');
			}
			else {
				buffer.append(ch);
			}

			last = ch;
		}
		return buffer.toString().trim();
	}

	private boolean isSurroundedByCharacters(char last, char next) {
		if (last == NULL_CHAR || next == NULL_CHAR) {
			return false;
		}
		return Character.isLetterOrDigit(last) && Character.isLetterOrDigit(next);
	}

	/**
	 * This method separates the parameters as strings.
	 * This is more complicated then one might initially think.
	 * Reason being, you need to take into account nested templates
	 * and function pointers.
	 */
	private List<DemangledDataType> parseParameters(String parameterString) {
		List<String> parameterStrings = tokenizeParameters(parameterString);
		List<DemangledDataType> parameters = convertIntoParameters(parameterStrings);
		return parameters;
	}

	private List<String> tokenizeParameters(String parameterString) {
		List<String> parameters = new ArrayList<>();

		if (parameterString.length() == 0) {
			return parameters;
		}

		// note: this matches the syntax of bob( const(param1, param2)), where for some
		// reason the demangled symbol has const() around the params.  After research, this is seen
		// when demangling functions that have const at the end, such as bob(param1, param2) const;
		Matcher matcher = UNNECESSARY_PARENS_PATTERN.matcher(parameterString);
		if (matcher.matches()) {
			parameterString = matcher.group(2);
		}

		if (StringUtils.isBlank(parameterString)) {
			return parameters;
		}

		int depth = 0;
		int startIndex = 0;
		for (int i = 0; i < parameterString.length(); ++i) {
			char ch = parameterString.charAt(i);
			if (ch == ',' && depth == 0) {
				String ps = parameterString.substring(startIndex, i);
				parameters.add(ps.trim());
				startIndex = i + 1;
			}
			else if (ch == '<') {
				++depth;
			}
			else if (ch == '>') {
				--depth;
			}
			else if (ch == '(') {
				//
				// Move past both sets of parents for function pointers
				// 		e.g., unsigned long (*)(long const &)
				// Also, array pointer/refs
				//  	e.g., short (&)[7]
				//

				// check for array case
				matcher =
					ARRAY_POINTER_REFERENCE_PIECE_PATTERN.matcher(parameterString.substring(i));
				if (matcher.find()) {
					int start = matcher.start();
					if (start == 0) {
						// matched something like: (&)[7]

						// end is the offset *after* the last char matched, so subtract 1, since
						// we want to next process the character after the end of the match and
						// the loop is going to increment i after we continue.
						int end = matcher.end() - 1;
						i += end;
						continue;// skip past the matching array syntax
					}
				}

				matcher = CAST_PATTERN.matcher(parameterString.substring(i));
				if (matcher.find()) {
					int start = matcher.start();
					if (start == 0) {
						// matched something like: (unsigned)4294967295

						// end is the offset *after* the last char matched, so subtract 1, since
						// we want to next process the character after the end of the match and
						// the loop is going to increment i after we continue.
						int end = matcher.end() - 1;
						i += end;
						continue;// skip past the matching cast syntax
					}
				}

				i = getFunctionPointerCloseParen(parameterString, i);
			}
		}
		if (startIndex < parameterString.length()) {
			String ps = parameterString.substring(startIndex, parameterString.length());
			parameters.add(ps.trim());
		}
		return parameters;
	}

	private int getFunctionPointerCloseParen(String parameterString, int currentIndex) {
		int firstCloseParen = parameterString.indexOf(')', currentIndex);
		if (firstCloseParen == -1) {
			throw new DemanglerParseException(
				"Unable to find closing paren for parameter string: " + parameterString);
		}

		//
		// we wish to move past two sets of parens for function pointers; however, sometimes
		// we have code with only one set of parens; for example:
		//   unsigned long (*)(long const &)
		// or
		//   iterator<boost::function<void ()>
		//
		boolean foundNextStart = false;
		int length = parameterString.length();
		for (int i = currentIndex; i < length; i++) {
			char ch = parameterString.charAt(i);
			if (ch == ')') {
				return i;
			}
			else if (ch == '(') {
				foundNextStart = true;
			}
			else if (ch == ',') {
				if (!foundNextStart) {
					return firstCloseParen;// no new set of parens found
				}
			}
		}

		return firstCloseParen;
	}

	/**
	 * This method converts each parameter string into
	 * actual DemangledDataType objects.
	 */
	private List<DemangledDataType> convertIntoParameters(List<String> parameterStrings) {
		List<DemangledDataType> parameters = new ArrayList<>();

		for (String parameter : parameterStrings) {
			DemangledDataType ddt = parseDataType(parameter);
			parameters.add(ddt);
		}

		return parameters;
	}

	private DemangledDataType parseDataType(String fullDatatype) {

		Matcher castMatcher = CAST_PATTERN.matcher(fullDatatype);
		if (castMatcher.matches()) {
			// special case: template parameter with a cast (just make the datatype
			// be the name of the template parameter, since it will just be a display
			// attribute for the templated type)
			String value = castMatcher.group(0);// group 0 is the entire match
			return new DemangledDataType(value);
		}

		DemangledDataType ddt = createTypeInNamespace(fullDatatype);
		String datatype = ddt.getDemangledName();
		boolean finishedName = false;
		for (int i = 0; i < datatype.length(); ++i) {
			char ch = datatype.charAt(i);

			if (!finishedName && isDataTypeNameCharacter(ch)) {
				continue;
			}

			if (!finishedName) {
				finishedName = true;

				if (VAR_ARGS.equals(datatype)) {
					ddt.setVarArgs();
				}
				else {
					String name = datatype.substring(0, i).trim();
					ddt.setName(name);
				}
			}

			if (ch == ' ') {
				continue;
			}
			if (ch == '<') {//start of template
				int contentStart = i + 1;
				// int templateEnd = getTemplateEndIndex(datatype, contentStart);
				int templateEnd = findTemplateEnd(datatype, i);
				if (templateEnd == -1 || templateEnd > datatype.length()) {
					throw new DemanglerParseException("Did not find ending to template");
				}

				String templateContent = datatype.substring(contentStart, templateEnd);
				DemangledTemplate template = parseTemplate(templateContent);
				ddt.setTemplate(template);
				i = templateEnd;
			}
			else if (ch == '(') {// start of function pointer or array ref/pointer
				//
				// function pointer
				// 		e.g., unsigned long (*)(long const &)
				// array pointer/refs
				//  	e.g., short (&)[7]
				//

				// check for array case
				Matcher arrayMatcher = ARRAY_POINTER_REFERENCE_PATTERN.matcher(datatype);
				if (arrayMatcher.matches()) {
					Demangled namespace = ddt.getNamespace();
					String name = arrayMatcher.group(1);// group 0 is the entire string
					ddt = parseArrayPointerOrReference(datatype, name);
					ddt.setNamespace(namespace);
					i = arrayMatcher.end();
				}
				else {
					int startParenCount =
						StringUtilities.countOccurrences(datatype.substring(i), '(');
					boolean hasPointerParens = startParenCount == 2;
					if (hasPointerParens) {
						Demangled namespace = ddt.getNamespace();
						DemangledFunctionPointer dfp = parseFunctionPointer(datatype);
						int firstParenEnd = datatype.indexOf(')', i + 1);
						int secondParenEnd = datatype.indexOf(')', firstParenEnd + 1);
						if (secondParenEnd == -1) {
							throw new DemanglerParseException(
								"Did not find ending to closure: " + datatype);
						}

						dfp.getReturnType().setNamespace(namespace);
						ddt = dfp;
						i = secondParenEnd + 1; // two sets of parens (normal case)
					}
					else {

						// parse as a function pointer, but display as a function
						Demangled namespace = ddt.getNamespace();
						DemangledFunctionPointer dfp = parseFunction(datatype, i);
						int firstParenEnd = datatype.indexOf(')', i + 1);
						if (firstParenEnd == -1) {
							throw new DemanglerParseException(
								"Did not find ending to closure: " + datatype);
						}

						dfp.getReturnType().setNamespace(namespace);
						ddt = dfp;
						i = firstParenEnd + 1;// two sets of parens (normal case)
					}
				}
			}
			else if (ch == '*') {
				ddt.incrementPointerLevels();
				continue;
			}
			else if (ch == '&') {
				if (!ddt.isReference()) {
					ddt.setReference();
				}
				else {
					ddt.incrementPointerLevels();
				}
				continue;
			}
			else if (ch == '[') {
				ddt.setArray(ddt.getArrayDimensions() + 1);
				i = datatype.indexOf(']', i + 1);
				continue;
			}

			String substr = datatype.substring(i);

			if (substr.startsWith("const")) {
				ddt.setConst();
				i += 4;
			}
			else if (substr.startsWith("struct")) {
				ddt.setStruct();
				i += 5;
			}
			else if (substr.startsWith("class")) {
				ddt.setClass();
				i += 4;
			}
			else if (substr.startsWith("enum")) {
				ddt.setEnum();
				i += 3;
			}
			else if (ddt.getName().equals("long")) {
				if (substr.startsWith("long")) {
					ddt.setName(DemangledDataType.LONG_LONG);
					i += 3;
				}
				else if (substr.startsWith("double")) {
					ddt.setName(DemangledDataType.LONG_DOUBLE);
					i += 5;
				}
			}
			// unsigned can also mean unsigned long, int
			else if (ddt.getName().equals("unsigned")) {
				ddt.setUnsigned();
				if (substr.startsWith("long")) {
					ddt.setName(DemangledDataType.LONG);
					i += 3;
				}
				else if (substr.startsWith("int")) {
					ddt.setName(DemangledDataType.INT);
					i += 2;
				}
				else if (substr.startsWith("short")) {
					ddt.setName(DemangledDataType.SHORT);
					i += 4;
				}
				else if (substr.startsWith("char")) {
					ddt.setName(DemangledDataType.CHAR);
					i += 3;
				}
			}
		}
		return ddt;
	}

	private boolean isDataTypeNameCharacter(char ch) {

		/*
			Note: really, this should just be checking a list of known disallowed characters, 
				  which is something like:
				  
				  <,>,(,),&,*,[,]
		
		 		  It seems like the current code below is unnecessarily restrictive
		 */

		//@formatter:off
		return Character.isLetter(ch) || 
			   Character.isDigit(ch) || 
			   ch == ':' || 
			   ch == '_' ||
			   ch == '$';
		//@formatter:on
	}

	/**
	 * Scans the given string from the given offset looking for a template and reporting the 
	 * index of the closing template character '>' or -1 if no templates are found
	 *  
	 * @param string the input string
	 * @param start the start position within the string
	 * @return the template end index; -1 if no templates found
	 */
	private int findTemplateEnd(String string, int start) {

		boolean found = false;
		int depth = 0;
		for (int i = start; i < string.length(); i++) {
			switch (string.charAt(i)) {
				case '<':
					depth++;
					found = true;
					break;
				case '>':
					depth--;
					break;
			}

			if (found && depth == 0) {
				return i;
			}
		}

		return -1;
	}

	// assumption: the given index is in a template
	// Walk backwards to find the template start
	private int findMatchingTemplateStart(String string, int templateEnd) {

		int depth = 1;
		for (int i = templateEnd - 1; i >= 0; i--) {
			switch (string.charAt(i)) {
				case '<':
					depth--;
					break;
				case '>':
					depth++;
					break;
			}

			if (depth == 0) {
				return i;// found our opening tag
			}
		}

		return -1;
	}

	private DemangledDataType createTypeInNamespace(String name) {
		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();

		DemangledType namespace = null;
		if (names.size() > 1) {
			namespace = convertToNamespaces(names.subList(0, names.size() - 1));
		}

		String datatypeName = names.get(names.size() - 1);
		DemangledDataType ddt = new DemangledDataType(datatypeName);
		ddt.setName(datatypeName);
		ddt.setNamespace(namespace);
		return ddt;
	}

	private void setNameAndNamespace(DemangledObject object, String name) {

		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();

		DemangledType namespace = null;
		if (names.size() > 1) {
			namespace = convertToNamespaces(names.subList(0, names.size() - 1));
		}

		String objectName = names.get(names.size() - 1);

		object.setName(objectName);
		object.setNamespace(namespace);
	}

	private void setNamespace(DemangledObject object, String name) {

		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();
		object.setNamespace(convertToNamespaces(names));
	}

	private DemangledTemplate parseTemplate(String templateStr) {
		List<DemangledDataType> parameters = parseParameters(templateStr);
		DemangledTemplate template = new DemangledTemplate();
		for (DemangledDataType parameter : parameters) {
			template.addParameter(parameter);
		}
		return template;
	}

	private DemangledDataType parseArrayPointerOrReference(String datatype, String name) {
		// int (*)[8]
		// char (&)[7]

		DemangledDataType ddt = new DemangledDataType(name);
		Matcher matcher = ARRAY_POINTER_REFERENCE_PATTERN.matcher(datatype);
		matcher.find();
		String type = matcher.group(3);
		if (type.equals("*")) {
			ddt.incrementPointerLevels();
		}
		else if (type.equals("&")) {
			ddt.setReference();
		}
		else {
			throw new DemanglerParseException("Unexpected charater inside of parens: " + type);
		}

		String arraySubscripts = matcher.group(4);
		int n = StringUtilities.countOccurrences(arraySubscripts, '[');
		ddt.setArray(n);

		return ddt;
	}

	private DemangledFunctionPointer parseFunctionPointer(String functionString) {
		//unsigned long (*)(long const &)

		int parenStart = functionString.indexOf('(');
		int parenEnd = functionString.indexOf(')');

		String returnType = functionString.substring(0, parenStart).trim();

		int paramStart = functionString.indexOf('(', parenEnd + 1);
		int paramEnd = functionString.lastIndexOf(')');
		String parameters = functionString.substring(paramStart + 1, paramEnd);
		return createFunctionPointer(parameters, returnType);
	}

	private DemangledFunctionPointer parseFunction(String functionString, int offset) {
		//unsigned long (long const &)

		int parenStart = functionString.indexOf('(', offset);
		int parenEnd = functionString.indexOf(')', parenStart + 1);

		String returnType = functionString.substring(0, parenStart).trim();

		int paramStart = parenStart;
		int paramEnd = parenEnd;
		String parameters = functionString.substring(paramStart + 1, paramEnd);
		DemangledFunctionPointer dfp = createFunctionPointer(parameters, returnType);
		dfp.setDisplayFunctionPointerParens(false);
		return dfp;
	}

	private DemangledFunctionPointer createFunctionPointer(String paramerterString,
			String returnType) {

		List<DemangledDataType> parameters = parseParameters(paramerterString);

		DemangledFunctionPointer dfp = new DemangledFunctionPointer();
		dfp.setReturnType(parseDataType(returnType));
		for (DemangledDataType parameter : parameters) {
			dfp.addParameter(parameter);
		}
		return dfp;
	}

	private DemangledObject parseVariable(String demangled) {

		/*
		 	Examples:
		 	
		 		NS1::Function<>()::StructureName::StructureConstructor()
		 	
		 */

		String nameString = fixupInternalSeparators(demangled).trim();
		DemangledVariable variable = new DemangledVariable((String) null);
		setNameAndNamespace(variable, nameString);
		return variable;
	}

	/**
	 * Converts the list of names into a namespace demangled type.
	 * Given names = { "A", "B", "C" }, which represents "A::B::C".
	 * The following will be created {@literal "Namespace{A}->Namespace{B}->Namespace{C}"}
	 * and Namespace{C} will be returned.
	 * 
	 * <p>This method will also escape spaces and namespace separators inside of templates
	 * (see {@link #fixupInternalSeparators(String)}).
	 * 
	 * @param names the names to convert
	 * @return the newly created type
	 */
	private DemangledType convertToNamespaces(List<String> names) {
		if (names.size() == 0) {
			return null;
		}
		int index = names.size() - 1;
		String rawName = names.get(index);
		String escapedName = fixupInternalSeparators(rawName);
		DemangledType myNamespace = new DemangledType(escapedName);
		myNamespace.setOriginalDemangled(rawName);

		DemangledType namespace = myNamespace;
		while (--index >= 0) {
			rawName = names.get(index);
			escapedName = fixupInternalSeparators(rawName);
			DemangledType parentNamespace = new DemangledType(escapedName);
			myNamespace.setOriginalDemangled(rawName);
			namespace.setNamespace(parentNamespace);
			namespace = parentNamespace;
		}
		return myNamespace;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private abstract class SpecialPrefixHandler {

		protected String demangled;
		protected String prefix;
		protected String name;
		protected String type;

		abstract String getType();

		abstract DemangledObject build(Demangled namespace);

		@Override
		public String toString() {
			ToStringBuilder builder = new ToStringBuilder(this, ToStringStyle.JSON_STYLE);
			return builder
					.append("name", name)
					.append("prefix", prefix)
					.append("type", type)
					.append("demangled", demangled)
					.toString();
		}
	}

	private class ItemInNamespaceHandler extends SpecialPrefixHandler {

		ItemInNamespaceHandler(String demangled) {
			this.demangled = demangled;
			this.type = demangled;
		}

		ItemInNamespaceHandler(String demangled, String prefix, String item) {
			this.demangled = demangled;
			this.prefix = prefix;
			this.type = item;
		}

		@Override
		String getType() {
			return type;
		}

		@Override
		DemangledObject build(Demangled namespace) {
			DemangledObject demangledObject = parseItemInNamespace(type);
			return demangledObject;
		}
	}

	private class ThunkHandler extends SpecialPrefixHandler {

		ThunkHandler(String demangled, String prefix, String item) {
			this.demangled = demangled;
			this.prefix = prefix;
			this.type = item;
		}

		@Override
		String getType() {
			return type;
		}

		@Override
		DemangledObject build(Demangled demangledObject) {

			DemangledFunction function = (DemangledFunction) demangledObject;
			function.setSignature(type);
			function.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);

			DemangledThunk thunk = new DemangledThunk(function);
			if (prefix.contains(COVARIANT_RETURN_THUNK)) {
				thunk.setCovariantReturnThunk();
			}

			thunk.setSignaturePrefix(prefix);
			return thunk;
		}
	}

	private class TypeInfoNameHandler extends SpecialPrefixHandler {

		TypeInfoNameHandler(String demangled, String prefix) {
			this.demangled = demangled;
			this.prefix = prefix;
		}

		@Override
		String getType() {
			String classname = demangled.substring(prefix.length()).trim();
			type = classname;
			return type;
		}

		@Override
		DemangledObject build(Demangled namespace) {
			DemangledString demangledString =
				new DemangledString("typeinfo-name", type, -1/*unknown length*/, false);
			demangledString.setSpecialPrefix("typeinfo name for ");
			String namespaceString = fixupInternalSeparators(type);
			setNamespace(demangledString, namespaceString);
			return demangledString;
		}
	}

	private class AddressTableHandler extends SpecialPrefixHandler {

		AddressTableHandler(String demangled, String prefix, String type) {
			this.demangled = demangled;
			this.prefix = prefix;
			this.type = type;

			Matcher matcher = ENDS_WITH_DIGITS_PATTERN.matcher(demangled);
			if (matcher.matches()) {
				// ends with a number, strip it off
				int oldLength = demangled.length();
				this.demangled = matcher.group(1);
				int delta = oldLength - this.demangled.length();
				this.type = type.substring(0, type.length() - delta);
			}
		}

		@Override
		String getType() {

			/*
			 Samples:
			 	 prefix: construction vtable for 
			 	 name:   construction-vtable
			 	 
			 	 prefix: vtable for 
			 	 name:   vtable
			 
			 	 prefix: typeinfo name for 
			 	 name:   typeinfo-name
			 	 
			 	 prefix: covariant return thunk
			 	 name:   covariant-return
			*/
			int pos = prefix.trim().lastIndexOf(' ');
			name = prefix.substring(0, pos).replace(' ', '-');
			return type;
		}

		@Override
		DemangledObject build(Demangled namespace) {
			DemangledAddressTable addressTable = new DemangledAddressTable(name, true);
			addressTable.setNamespace(namespace);
			return addressTable;
		}
	}

	private abstract class OperatorHandler {

		protected Matcher matcher;

		abstract boolean matches(String s);

		abstract DemangledObject build();
	}

	private class OverloadOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangled) {
			matcher = OVERLOAD_OPERATOR_PATTERN.matcher(demangled);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {

			//
			// An example to follow along with:
			//
			// 'overloaded operator' syntax is:
			// [return_type] operator<operator_chars>[templates](parameters)
			//
			// Namespace::Class::operator Namespace::Type()
			//
			// NS1::operator<(NS1::Coordinate const &,NS1::Coordinate const &)
			//

			// prefix: return_type operator operator_chars[templates]
			// 		   (everything before the parameters)
			String operatorPrefix = matcher.group(1);
			//String operatorChars = matcher.group(2);
			String parametersText = matcher.group(3);
			//String trailing = matcher.group(4);

			String returnTypeText = "undefined";
			String operatorName = operatorPrefix;

			operatorPrefix = fixupInternalSeparators(operatorPrefix);
			returnTypeText = fixupInternalSeparators(returnTypeText);
			DemangledDataType returnType = createTypeInNamespace(returnTypeText);

			DemangledFunction function = new DemangledFunction((String) null);
			function.setOverloadedOperator(true);
			function.setReturnType(returnType);

			operatorName = fixupInternalSeparators(operatorName);
			setNameAndNamespace(function, operatorName);

			List<DemangledDataType> parameters = parseParameters(parametersText);
			for (DemangledDataType parameter : parameters) {
				function.addParameter(parameter);
			}

			return function;
		}
	}

	private class ConversionOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangled) {
			matcher = CONVERSION_OPERATOR_PATTERN.matcher(demangled);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {

			// this will yield:
			// fullName: 		NS1::Foo::operator
			// fullReturnType:  std::string
			String fullName = matcher.group(1);// group 0 is the entire match string
			String fullReturnType = matcher.group(2);

			boolean isConst = false;
			int index = fullReturnType.indexOf(CONST_KEYWORD);
			if (index != -1) {
				fullReturnType = fullReturnType.replace(CONST_KEYWORD, "");
				isConst = true;
			}

			DemangledFunction method = new DemangledFunction((String) null);
			DemangledDataType returnType = parseDataType(fullReturnType);
			if (isConst) {
				returnType.setConst();
			}
			method.setReturnType(returnType);

			// 'conversion operator' syntax is 'operator <name/type>()'
			// assume fullName endsWith '::operator'
			int operatorIndex = fullName.lastIndexOf("::operator");
			String namespace = fullName.substring(0, operatorIndex);

			String templatelessNamespace = stripOffTemplates(namespace);
			setNamespace(method, templatelessNamespace);

			// shortReturnType: string
			String templatelessReturnType = stripOffTemplates(fullReturnType);
			SymbolPath path = new SymbolPath(templatelessReturnType);
			String shortReturnTypeName = path.getName();

			//
			// The preferred name: 'operator basic_string()'
			//
			// Ghidra does not allow spaces in the name or extra parens. So, make a name that is
			// as clear as possible in describing the construct.
			//
			method.setName("operator.cast.to." + shortReturnTypeName);

			method.setSignature(fullName + " " + fullReturnType);
			method.setOverloadedOperator(true);

			return method;
		}
	}

	private class NewOrDeleteOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangler) {
			matcher = NEW_DELETE_OPERATOR_PATTERN.matcher(demangler);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {

			String operatorText = matcher.group(1);// group 0 is the entire match string
			String operatorName = matcher.group(2);
			String arrayBrackets = matcher.group(3);
			String parametersText = matcher.group(4);

			DemangledFunction function = new DemangledFunction((String) null);
			function.setOverloadedOperator(true);
			DemangledDataType returnType = new DemangledDataType("void");
			if (operatorName.startsWith("new")) {
				returnType.incrementPointerLevels();
			}

			function.setReturnType(returnType);

			// 'new operator' syntax is 'operator <name/type>()', where the
			// operator itself could be in a class namespace
			setNameAndNamespace(function, operatorText);

			List<DemangledDataType> parameters = parseParameters(parametersText);
			for (DemangledDataType parameter : parameters) {
				function.addParameter(parameter);
			}

			//
			// The preferred name: 'operator new()'
			//
			// Ghidra does not allow spaces in the name or extra parens. So, make a name that is
			// as clear as possible in describing the construct.
			//
			String name = operatorName;
			if (arrayBrackets != null) {
				name += "[]";
			}
			function.setName("operator." + name);

			function.setSignature(operatorText + " " + operatorName);

			return function;
		}
	}

	private class ParameterLocator {
		int paramStart = -1;
		int paramEnd = -1;
		private String text;

		ParameterLocator(String text) {
			this.text = text;
			paramEnd = text.lastIndexOf(')');
			if (paramEnd < 0) {
				return;
			}
			if (isContainedWithinNamespace()) {
				// ignore param list associated with namespace specification
				paramEnd = -1;
				return;
			}
			paramStart = findParameterStart(text, paramEnd);
			int templateEnd = findTemplateEnd(text, 0);
			int templateStart = -1;
			if (templateEnd != -1) {
				templateStart = findMatchingTemplateStart(text, templateEnd);
			}
			if (paramStart > templateStart && paramStart < templateEnd) {
				// ignore parentheses inside of templates (they are cast operators)
				paramStart = -1;
				paramEnd = -1;
			}
		}

		@Override
		public String toString() {
			ToStringBuilder builder = new ToStringBuilder(this, ToStringStyle.JSON_STYLE);
			return builder
					.append("texf", text)
					.append("paramStart", paramStart)
					.append("paramEnd", paramEnd)
					.toString();
		}

		private boolean isContainedWithinNamespace() {
			return (paramEnd < (text.length() - 1)) && (':' == text.charAt(paramEnd + 1));
		}

		int getParamStart() {
			return paramStart;
		}

		int getParamEnd() {
			return paramEnd;
		}

		boolean hasParameters() {
			return paramStart != -1 && paramEnd != -1;
		}

		// walks backwards to find the start of the parameter list
		private int findParameterStart(String demangled, int end) {

			int depth = 0;
			for (int i = end - 1; i >= 0; --i) {
				char ch = demangled.charAt(i);
				if (ch == '(' && depth == 0) {
					return i;
				}
				else if (ch == '>' || ch == ')') {
					++depth;
				}
				else if (ch == '<' || ch == '(') {
					depth--;
				}
			}
			return -1;
		}
	}

	private class LambdaName {

		private String fullText;
		private String params;
		private String trailing;

		LambdaName(String fullText, String params, String trailing) {
			this.fullText = fullText;
			this.params = params;
			this.trailing = trailing;
		}

		String getFullText() {
			return fullText;
		}

		@Override
		public String toString() {
			ToStringBuilder builder = new ToStringBuilder(this, ToStringStyle.JSON_STYLE);
			return builder
					.append("fullText", fullText)
					.append("params", params)
					.append("trailing", trailing)
					.toString();
		}
	}
}
