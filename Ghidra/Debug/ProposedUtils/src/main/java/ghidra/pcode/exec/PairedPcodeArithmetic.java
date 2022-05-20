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
package ghidra.pcode.exec;

import java.math.BigInteger;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;

/**
 * An arithmetic composed from two.
 * 
 * <p>
 * The new arithmetic operates on tuples where each is subject to its respective arithmetic. One
 * exception is {@link #isTrue(Entry)}, which is typically used to control branches. This arithmetic
 * defers to left ("control") arithmetic.
 * 
 * @param <L> the type of the left ("control") element
 * @param <R> the type of the right ("rider") element
 */
public class PairedPcodeArithmetic<L, R> implements PcodeArithmetic<Pair<L, R>> {
	private final PcodeArithmetic<L> leftArith;
	private final PcodeArithmetic<R> rightArith;

	/**
	 * Construct a composed arithmetic from the given two
	 * 
	 * @param leftArith the left ("control") arithmetic
	 * @param rightArith the right ("rider") arithmetic
	 */
	public PairedPcodeArithmetic(PcodeArithmetic<L> leftArith, PcodeArithmetic<R> rightArith) {
		this.leftArith = leftArith;
		this.rightArith = rightArith;
	}

	@Override
	public Pair<L, R> unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, Pair<L, R> in1) {
		return new ImmutablePair<>(
			leftArith.unaryOp(op, sizeout, sizein1, in1.getLeft()),
			rightArith.unaryOp(op, sizeout, sizein1, in1.getRight()));
	}

	@Override
	public Pair<L, R> binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, Pair<L, R> in1,
			int sizein2, Pair<L, R> in2) {
		return new ImmutablePair<>(
			leftArith.binaryOp(op, sizeout, sizein1, in1.getLeft(), sizein2, in2.getLeft()),
			rightArith.binaryOp(op, sizeout, sizein1, in1.getRight(), sizein2, in2.getRight()));
	}

	@Override
	public Pair<L, R> fromConst(long value, int size) {
		return new ImmutablePair<>(leftArith.fromConst(value, size),
			rightArith.fromConst(value, size));
	}

	@Override
	public Pair<L, R> fromConst(BigInteger value, int size, boolean isContextreg) {
		return new ImmutablePair<>(leftArith.fromConst(value, size, isContextreg),
			rightArith.fromConst(value, size, isContextreg));
	}

	@Override
	public boolean isTrue(Pair<L, R> cond) {
		return leftArith.isTrue(cond.getLeft());
	}

	@Override
	public BigInteger toConcrete(Pair<L, R> value, boolean isContextreg) {
		return leftArith.toConcrete(value.getLeft(), isContextreg);
	}

	@Override
	public Pair<L, R> sizeOf(Pair<L, R> value) {
		return Pair.of(
			leftArith.sizeOf(value.getLeft()),
			rightArith.sizeOf(value.getRight()));
	}

	/**
	 * Get the left ("control") arithmetic
	 * 
	 * @return the arithmetic
	 */
	public PcodeArithmetic<L> getLeft() {
		return leftArith;
	}

	/**
	 * Get the right ("rider") arithmetic
	 * 
	 * @return the arithmetic
	 */
	public PcodeArithmetic<R> getRight() {
		return rightArith;
	}
}
