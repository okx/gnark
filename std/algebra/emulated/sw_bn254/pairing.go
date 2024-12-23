package sw_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bn254.Ext12
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g2     *G2
	bTwist *fields_bn254.E2
	g2gen  *G2Affine
}

type GTEl = fields_bn254.E12

func NewGTEl(v bn254.GT) GTEl {
	return GTEl{
		C0: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C0.B0.A0),
				A1: emulated.ValueOf[BaseField](v.C0.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C0.B1.A0),
				A1: emulated.ValueOf[BaseField](v.C0.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C0.B2.A0),
				A1: emulated.ValueOf[BaseField](v.C0.B2.A1),
			},
		},
		C1: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C1.B0.A0),
				A1: emulated.ValueOf[BaseField](v.C1.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C1.B1.A0),
				A1: emulated.ValueOf[BaseField](v.C1.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[BaseField](v.C1.B2.A0),
				A1: emulated.ValueOf[BaseField](v.C1.B2.A1),
			},
		},
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	bTwist := fields_bn254.E2{
		A0: emulated.ValueOf[BaseField]("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
		A1: emulated.ValueOf[BaseField]("266929791119991161246907387137283842545076965332900288569378510910307636690"),
	}
	return &Pairing{
		api:    api,
		Ext12:  fields_bn254.NewExt12(api),
		curveF: ba,
		curve:  curve,
		g2:     NewG2(api),
		bTwist: &bTwist,
	}, nil
}

func (pr Pairing) generators() *G2Affine {
	if pr.g2gen == nil {
		_, _, _, g2gen := bn254.Generators()
		cg2gen := NewG2AffineFixed(g2gen)
		pr.g2gen = &cg2gen
	}
	return pr.g2gen
}

// FinalExponentiation computes the exponentiation eᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r.
//
// We use instead d'= s ⋅ d, where s is the cofactor
//
//	2x₀(6x₀²+3x₀+1)
//
// and r does NOT divide d'
//
// FinalExponentiation returns a decompressed element in E12.
//
// This is the safe version of the method where e may be {-1,1}. If it is known
// that e ≠ {-1,1} then using the unsafe version of the method saves
// considerable amount of constraints. When called with the result of
// [MillerLoop], then current method is applicable when length of the inputs to
// Miller loop is 1.
func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	return pr.finalExponentiation(e, false)
}

// FinalExponentiationUnsafe computes the exponentiation eᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r.
//
// We use instead d'= s ⋅ d, where s is the cofactor
//
//	2x₀(6x₀²+3x₀+1)
//
// and r does NOT divide d'
//
// FinalExponentiationUnsafe returns a decompressed element in E12.
//
// This is the unsafe version of the method where e may NOT be {-1,1}. If e ∈
// {-1, 1}, then there exists no valid solution to the circuit. This method is
// applicable when called with the result of [MillerLoop] method when the length
// of the inputs to Miller loop is 1.
func (pr Pairing) FinalExponentiationUnsafe(e *GTEl) *GTEl {
	return pr.finalExponentiation(e, true)
}

// finalExponentiation computes the exponentiation eᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r.
//
// We use instead d'= s ⋅ d, where s is the cofactor
//
//	2x₀(6x₀²+3x₀+1)
//
// and r does NOT divide d'
//
// finalExponentiation returns a decompressed element in E12
func (pr Pairing) finalExponentiation(e *GTEl, unsafe bool) *GTEl {

	// 1. Easy part
	// (p⁶-1)(p²+1)
	var selector1, selector2 frontend.Variable
	_dummy := pr.Ext6.One()

	if unsafe {
		// The Miller loop result is ≠ {-1,1}, otherwise this means P and Q are
		// linearly dependent and not from G1 and G2 respectively.
		// So e ∈ G_{q,2} \ {-1,1} and hence e.C1 ≠ 0.
		// Nothing to do.

	} else {
		// However, for a product of Miller loops (n>=2) this might happen.  If this is
		// the case, the result is 1 in the torus. We assign a dummy value (1) to e.C1
		// and proceed further.
		selector1 = pr.Ext6.IsZero(&e.C1)
		e.C1.B0.A0 = *pr.curveF.Select(selector1, pr.curveF.One(), &e.C1.B0.A0)
	}

	// Torus compression absorbed:
	// Raising e to (p⁶-1) is
	// e^(p⁶) / e = (e.C0 - w*e.C1) / (e.C0 + w*e.C1)
	//            = (-e.C0/e.C1 + w) / (-e.C0/e.C1 - w)
	// So the fraction -e.C0/e.C1 is already in the torus.
	// This absorbs the torus compression in the easy part.
	c := pr.Ext6.DivUnchecked(&e.C0, &e.C1)
	c = pr.Ext6.Neg(c)
	t0 := pr.FrobeniusSquareTorus(c)
	c = pr.MulTorus(t0, c)

	// 2. Hard part (up to permutation)
	// 2x₀(6x₀²+3x₀+1)(p⁴-p²+1)/r
	// Duquesne and Ghammam
	// https://eprint.iacr.org/2015/192.pdf
	// Fuentes et al. (alg. 6)
	// performed in torus compressed form
	t0 = pr.ExptTorus(c)
	t0 = pr.InverseTorus(t0)
	t0 = pr.SquareTorus(t0)
	t1 := pr.SquareTorus(t0)
	t1 = pr.MulTorus(t0, t1)
	t2 := pr.ExptTorus(t1)
	t2 = pr.InverseTorus(t2)
	t3 := pr.InverseTorus(t1)
	t1 = pr.MulTorus(t2, t3)
	t3 = pr.SquareTorus(t2)
	t4 := pr.ExptTorus(t3)
	t4 = pr.MulTorus(t1, t4)
	t3 = pr.MulTorus(t0, t4)
	t0 = pr.MulTorus(t2, t4)
	t0 = pr.MulTorus(c, t0)
	t2 = pr.FrobeniusTorus(t3)
	t0 = pr.MulTorus(t2, t0)
	t2 = pr.FrobeniusSquareTorus(t4)
	t0 = pr.MulTorus(t2, t0)
	t2 = pr.InverseTorus(c)
	t2 = pr.MulTorus(t2, t3)
	t2 = pr.FrobeniusCubeTorus(t2)

	var result GTEl
	// MulTorus(t0, t2) requires t0 ≠ -t2. When t0 = -t2, it means the
	// product is 1 in the torus.
	if unsafe {
		// For a single pairing, this does not happen because the pairing is non-degenerate.
		result = *pr.DecompressTorus(pr.MulTorus(t2, t0))
	} else {
		// For a product of pairings this might happen when the result is expected to be 1.
		// We assign a dummy value (1) to t0 and proceed further.
		// Finally we do a select on both edge cases:
		//   - Only if seletor1=0 and selector2=0, we return MulTorus(t2, t0) decompressed.
		//   - Otherwise, we return 1.
		_sum := pr.Ext6.Add(t0, t2)
		selector2 = pr.Ext6.IsZero(_sum)
		t0 = pr.Ext6.Select(selector2, _dummy, t0)
		selector := pr.api.Mul(pr.api.Sub(1, selector1), pr.api.Sub(1, selector2))
		result = *pr.Select(selector, pr.DecompressTorus(pr.MulTorus(t2, t0)), pr.One())
	}

	return &result
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroups. See AssertIsOnG1 and AssertIsOnG2.
func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.finalExponentiation(res, len(P) == 1)
	return res, nil
}

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups. See AssertIsOnG1 and AssertIsOnG2.
func (pr Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return err

	}
	// We perform the easy part of the final exp to push f to the cyclotomic
	// subgroup so that AssertFinalExponentiationIsOne is carried with optimized
	// cyclotomic squaring (e.g. Karabina12345).
	//
	// f = f^(p⁶-1)(p²+1)
	buf := pr.Conjugate(f)
	buf = pr.DivUnchecked(buf, f)
	f = pr.FrobeniusSquare(buf)
	f = pr.Mul(f, buf)

	pr.AssertFinalExponentiationIsOne(f)

	return nil
}

func (pr Pairing) IsEqual(x, y *GTEl) frontend.Variable {
	return pr.Ext12.IsEqual(x, y)
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}

func (pr Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr Pairing) computeTwistEquation(Q *G2Affine) (left, right *fields_bn254.E2) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=3/(9+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 3/(9+u), and continue
	selector := pr.api.And(pr.Ext2.IsZero(&Q.P.X), pr.Ext2.IsZero(&Q.P.Y))
	b := pr.Ext2.Select(selector, pr.Ext2.Zero(), pr.bTwist)

	left = pr.Ext2.Square(&Q.P.Y)
	right = pr.Ext2.Square(&Q.P.X)
	right = pr.Ext2.Mul(right, &Q.P.X)
	right = pr.Ext2.Add(right, b)
	return left, right
}

func (pr Pairing) AssertIsOnTwist(Q *G2Affine) {
	left, right := pr.computeTwistEquation(Q)
	pr.Ext2.AssertIsEqual(left, right)
}

// IsOnTwist returns a boolean indicating if the G2 point is in the twist.
func (pr Pairing) IsOnTwist(Q *G2Affine) frontend.Variable {
	left, right := pr.computeTwistEquation(Q)
	diff := pr.Ext2.Sub(left, right)
	return pr.Ext2.IsZero(diff)
}

func (pr Pairing) AssertIsOnG1(P *G1Affine) {
	// BN254 has a prime order, so we only
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)
}

func (pr Pairing) computeG2ShortVector(Q *G2Affine) (_Q *G2Affine) {
	// [x₀]Q
	xQ := pr.g2.scalarMulBySeed(Q)
	// ψ([x₀]Q)
	psixQ := pr.g2.psi(xQ)
	// ψ²([x₀]Q) = -ϕ([x₀]Q)
	psi2xQ := pr.g2.phi(xQ)
	// ψ³([2x₀]Q)
	psi3xxQ := pr.g2.double(psi2xQ)
	psi3xxQ = pr.g2.psi(psi3xxQ)

	// _Q = ψ³([2x₀]Q) - ψ²([x₀]Q) - ψ([x₀]Q) - [x₀]Q
	_Q = pr.g2.sub(psi2xQ, psi3xxQ)
	_Q = pr.g2.sub(_Q, psixQ)
	_Q = pr.g2.sub(_Q, xQ)
	return _Q
}

func (pr Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	_Q := pr.computeG2ShortVector(Q)
	// [r]Q == 0 <==>  _Q == Q
	pr.g2.AssertIsEqual(Q, _Q)
}

// IsOnG2 returns a boolean indicating if the G2 point is in the subgroup. The
// method assumes that the point is already on the curve. Call
// [Pairing.AssertIsOnTwist] before to ensure point is on the curve.
func (pr Pairing) IsOnG2(Q *G2Affine) frontend.Variable {
	// 1 - is Q on curve
	isOnCurve := pr.IsOnTwist(Q)
	// 2 - is Q in the subgroup
	_Q := pr.computeG2ShortVector(Q)
	isInSubgroup := pr.g2.IsEqual(Q, _Q)
	return pr.api.And(isOnCurve, isInSubgroup)
}

// loopCounter = 6x₀+2 = 29793968203157093288
//
// in 2-NAF
var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

// MillerLoop computes the multi-Miller loop
// ∏ᵢ { fᵢ_{6x₀+2,Q}(P) · ℓᵢ_{[6x₀+2]Q,π(Q)}(P) · ℓᵢ_{[6x₀+2]Q+π(Q),-π²(Q)}(P) }
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := pr.computeLines(&Q[i].P)
			Q[i].Lines = &Qlines
		}
		lines[i] = *Q[i].Lines
	}
	return pr.millerLoopLines(P, lines)

}

// millerLoopLines computes the multi-Miller loop from points in G1 and precomputed lines in G2
func (pr Pairing) millerLoopLines(P []*G1Affine, lines []lineEvaluations) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	yInv := make([]*emulated.Element[BaseField], n)
	xNegOverY := make([]*emulated.Element[BaseField], n)

	for k := 0; k < n; k++ {
		// P are supposed to be on G1 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.Mul(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	var prodLines [5]*fields_bn254.E2
	res := pr.Ext12.One()

	// Compute f_{6x₀+2,Q}(P)
	// i = 64, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	// line evaluation at P[0]
	res = &fields_bn254.E12{
		C0: res.C0,
		C1: fields_bn254.E6{
			B0: *pr.MulByElement(&lines[0][0][64].R0, xNegOverY[0]),
			B1: *pr.MulByElement(&lines[0][0][64].R1, yInv[0]),
			B2: res.C1.B2,
		},
	}

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		// line evaluation at P[1]
		// ℓ × res
		prodLines = pr.Mul034By034(
			pr.MulByElement(&lines[1][0][64].R0, xNegOverY[1]),
			pr.MulByElement(&lines[1][0][64].R1, yInv[1]),
			&res.C1.B0,
			&res.C1.B1,
		)
		res = &fields_bn254.E12{
			C0: fields_bn254.E6{
				B0: *prodLines[0],
				B1: *prodLines[1],
				B2: *prodLines[2],
			},
			C1: fields_bn254.E6{
				B0: *prodLines[3],
				B1: *prodLines[4],
				B2: res.C1.B2,
			},
		}
	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy034 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		// line evaluation at P[1]
		// ℓ × res
		res = pr.Mul01234By034(
			prodLines,
			pr.MulByElement(&lines[2][0][64].R0, xNegOverY[2]),
			pr.MulByElement(&lines[2][0][64].R1, yInv[2]),
		)

		// k >= 3
		for k := 3; k < n; k++ {
			// line evaluation at P[k]
			// ℓ × res
			res = pr.MulBy034(
				res,
				pr.MulByElement(&lines[k][0][64].R0, xNegOverY[k]),
				pr.MulByElement(&lines[k][0][64].R1, yInv[k]),
			)
		}
	}

	for i := 63; i >= 0; i-- {
		res = pr.Square(res)

		if loopCounter[i] == 0 {
			// if number of lines is odd, mul last line by res
			// works for n=1 as well
			if n%2 != 0 {
				// ℓ × res
				res = pr.MulBy034(
					res,
					pr.MulByElement(&lines[n-1][0][i].R0, xNegOverY[n-1]),
					pr.MulByElement(&lines[n-1][0][i].R1, yInv[n-1]),
				)
			}

			// mul lines 2-by-2
			for k := 1; k < n; k += 2 {
				// ℓ × ℓ
				prodLines = pr.Mul034By034(
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k-1][0][i].R0, xNegOverY[k-1]),
					pr.MulByElement(&lines[k-1][0][i].R1, yInv[k-1]),
				)
				// (ℓ × ℓ) × res
				res = pr.MulBy01234(res, prodLines)
			}

		} else {
			for k := 0; k < n; k++ {
				// lines evaluations at P
				// and ℓ × ℓ
				prodLines := pr.Mul034By034(
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k][1][i].R1, yInv[k]),
				)
				// (ℓ × ℓ) × res
				res = pr.MulBy01234(res, prodLines)

			}
		}
	}

	// Compute  ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	// lines evaluations at P
	// and ℓ × ℓ
	for k := 0; k < n; k++ {
		prodLines := pr.Mul034By034(
			pr.MulByElement(&lines[k][0][65].R0, xNegOverY[k]),
			pr.MulByElement(&lines[k][0][65].R1, yInv[k]),
			pr.MulByElement(&lines[k][1][65].R0, xNegOverY[k]),
			pr.MulByElement(&lines[k][1][65].R1, yInv[k]),
		)
		// (ℓ × ℓ) × res
		res = pr.MulBy01234(res, prodLines)
	}

	return res, nil
}

// doubleAndAddStep doubles p1 and adds or subs p2 to the result in affine coordinates, based on the isSub boolean.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 or p1-p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *g2AffP, isSub bool) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y1-y2)/(x1-x2) or λ1 = (y1+y2)/(x1-x2) if isSub is true
	var n *fields_bn254.E2
	if isSub {
		n = pr.Ext2.Add(&p1.Y, &p2.Y)
	} else {
		n = pr.Ext2.Sub(&p1.Y, &p2.Y)
	}
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	λ1 := pr.Ext2.DivUnchecked(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.Ext2.Square(λ1)
	x3 = pr.Ext2.Sub(x3, pr.Ext2.Add(&p1.X, &p2.X))

	// omit y3 computation

	// compute line1
	line1.R0 = *λ1
	line1.R1 = *pr.Ext2.Mul(λ1, &p1.X)
	line1.R1 = *pr.Ext2.Sub(&line1.R1, &p1.Y)

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	d = pr.Ext2.Sub(x3, &p1.X)
	λ2 := pr.Ext2.DivUnchecked(n, d)
	λ2 = pr.Ext2.Add(λ2, λ1)
	λ2 = pr.Ext2.Neg(λ2)

	// compute x4 = λ2²-x1-x3
	x4 := pr.Ext2.Square(λ2)
	x4 = pr.Ext2.Sub(x4, pr.Ext2.Add(&p1.X, x3))

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y4 = pr.Ext2.Mul(λ2, y4)
	y4 = pr.Ext2.Sub(y4, &p1.Y)

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *λ2
	line2.R1 = *pr.Ext2.Mul(λ2, &p1.X)
	line2.R1 = *pr.Ext2.Sub(&line2.R1, &p1.Y)

	return &p, &line1, &line2
}

// doubleStep doubles p1 in affine coordinates, and evaluates the tangent line to p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	n = pr.Ext2.MulByConstElement(n, big.NewInt(3))
	d := pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	λ := pr.Ext2.DivUnchecked(n, d)

	// xr = λ²-2x
	xr := pr.Ext2.Square(λ)
	xr = pr.Ext2.Sub(xr, pr.Ext2.MulByConstElement(&p1.X, big.NewInt(2)))

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr = pr.Ext2.Mul(λ, yr)
	yr = pr.Ext2.Sub(yr, &p1.Y)

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &p, &line

}

// addStep adds p1 and p2 in affine coordinates, and evaluates the line through p1 and p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation) {

	// compute λ = (y2-y1)/(x2-x1)
	p2ypy := pr.Ext2.Sub(&p2.Y, &p1.Y)
	p2xpx := pr.Ext2.Sub(&p2.X, &p1.X)
	λ := pr.Ext2.DivUnchecked(p2ypy, p2xpx)

	// xr = λ²-x1-x2
	xr := pr.Ext2.Square(λ)
	xr = pr.Ext2.Sub(xr, pr.Ext2.Add(&p1.X, &p2.X))

	// yr = λ(x1-xr) - y1
	pxrx := pr.Ext2.Sub(&p1.X, xr)
	λpxrx := pr.Ext2.Mul(λ, pxrx)
	yr := pr.Ext2.Sub(λpxrx, &p1.Y)

	var res g2AffP
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &res, &line

}

// lineCompute computes the line through p1 and p2, but does not compute p1+p2.
func (pr Pairing) lineCompute(p1, p2 *g2AffP) *lineEvaluation {

	// compute λ = (y2+y1)/(x2-x1)
	qypy := pr.Ext2.Add(&p1.Y, &p2.Y)
	qxpx := pr.Ext2.Sub(&p1.X, &p2.X)
	λ := pr.Ext2.DivUnchecked(qypy, qxpx)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &line

}

// MillerLoopAndMul computes the Miller loop between P and Q
// and multiplies it in 𝔽p¹² by previous.
//
// This method is needed for evmprecompiles/ecpair.
func (pr Pairing) MillerLoopAndMul(P *G1Affine, Q *G2Affine, previous *GTEl) (*GTEl, error) {
	res, err := pr.MillerLoop([]*G1Affine{P}, []*G2Affine{Q})
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.Mul(res, previous)
	return res, err
}

// millerLoopAndFinalExpResult computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and returns the result.
func (pr Pairing) millerLoopAndFinalExpResult(P *G1Affine, Q *G2Affine, previous *GTEl) *GTEl {

	// hint the non-residue witness
	hint, err := pr.curveF.NewHint(millerLoopAndCheckFinalExpHint, 18, &P.X, &P.Y, &Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1, &previous.C0.B0.A0, &previous.C0.B0.A1, &previous.C0.B1.A0, &previous.C0.B1.A1, &previous.C0.B2.A0, &previous.C0.B2.A1, &previous.C1.B0.A0, &previous.C1.B0.A1, &previous.C1.B1.A0, &previous.C1.B1.A1, &previous.C1.B2.A0, &previous.C1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitness := fields_bn254.E12{
		C0: fields_bn254.E6{
			B0: fields_bn254.E2{A0: *hint[0], A1: *hint[1]},
			B1: fields_bn254.E2{A0: *hint[2], A1: *hint[3]},
			B2: fields_bn254.E2{A0: *hint[4], A1: *hint[5]},
		},
		C1: fields_bn254.E6{
			B0: fields_bn254.E2{A0: *hint[6], A1: *hint[7]},
			B1: fields_bn254.E2{A0: *hint[8], A1: *hint[9]},
			B2: fields_bn254.E2{A0: *hint[10], A1: *hint[11]},
		},
	}
	// constrain cubicNonResiduePower to be in Fp6
	cubicNonResiduePower := fields_bn254.E12{
		C0: fields_bn254.E6{
			B0: fields_bn254.E2{A0: *hint[12], A1: *hint[13]},
			B1: fields_bn254.E2{A0: *hint[14], A1: *hint[15]},
			B2: fields_bn254.E2{A0: *hint[16], A1: *hint[17]},
		},
		C1: (*pr.Ext6.Zero()),
	}

	// residueWitnessInv = 1 / residueWitness
	residueWitnessInv := pr.Inverse(&residueWitness)

	if Q.Lines == nil {
		Qlines := pr.computeLines(&Q.P)
		Q.Lines = &Qlines
	}
	lines := *Q.Lines

	// precomputations
	yInv := pr.curveF.Inverse(&P.Y)
	xNegOverY := pr.curveF.Mul(&P.X, yInv)
	xNegOverY = pr.curveF.Neg(xNegOverY)

	// init Miller loop accumulator to residueWitnessInv to share the squarings
	// of residueWitnessInv^{6x₀+2}
	res := residueWitnessInv

	// Compute f_{6x₀+2,Q}(P)
	for i := 64; i >= 0; i-- {
		res = pr.Square(res)

		switch loopCounter[i] {
		case 0:
			// ℓ × res
			res = pr.MulBy034(
				res,
				pr.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.MulByElement(&lines[0][i].R1, yInv),
			)
		case 1:
			// multiply by residueWitnessInv when bit=1
			res = pr.Mul(res, residueWitnessInv)
			// lines evaluations at P
			// and ℓ × ℓ
			prodLines := pr.Mul034By034(
				pr.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.MulByElement(&lines[0][i].R1, yInv),
				pr.MulByElement(&lines[1][i].R0, xNegOverY),
				pr.MulByElement(&lines[1][i].R1, yInv),
			)
			// (ℓ × ℓ) × res
			res = pr.MulBy01234(res, prodLines)
		case -1:
			// multiply by residueWitness when bit=-1
			res = pr.Mul(res, &residueWitness)
			// lines evaluations at P
			// and ℓ × ℓ
			prodLines := pr.Mul034By034(
				pr.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.MulByElement(&lines[0][i].R1, yInv),
				pr.MulByElement(&lines[1][i].R0, xNegOverY),
				pr.MulByElement(&lines[1][i].R1, yInv),
			)
			// (ℓ × ℓ) × res
			res = pr.MulBy01234(res, prodLines)
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}
	}

	// Compute  ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	// lines evaluations at P
	// and ℓ × ℓ
	prodLines := pr.Mul034By034(
		pr.MulByElement(&lines[0][65].R0, xNegOverY),
		pr.MulByElement(&lines[0][65].R1, yInv),
		pr.MulByElement(&lines[1][65].R0, xNegOverY),
		pr.MulByElement(&lines[1][65].R1, yInv),
	)
	// (ℓ × ℓ) × res
	res = pr.MulBy01234(res, prodLines)

	// multiply by previous multi-Miller function
	res = pr.Mul(res, previous)

	// Check that  res * cubicNonResiduePower * residueWitnessInv^λ' == 1
	// where λ' = q^3 - q^2 + q, with u the BN254 seed
	// and residueWitnessInv, cubicNonResiduePower from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{6x₀+2} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	t2 := pr.Mul(&cubicNonResiduePower, res)

	t1 := pr.FrobeniusCube(residueWitnessInv)
	t0 := pr.FrobeniusSquare(residueWitnessInv)
	t1 = pr.DivUnchecked(t1, t0)
	t0 = pr.Frobenius(residueWitnessInv)
	t1 = pr.Mul(t1, t0)

	t2 = pr.Mul(t2, t1)

	return t2
}

// IsMillerLoopAndFinalExpOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and and returns a boolean indicating if
// the result lies in the same equivalence class as the reduced pairing
// purported to be 1. This check replaces the final exponentiation step
// in-circuit and follows Section 4 of [On Proving Pairings] paper by A.
// Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr Pairing) IsMillerLoopAndFinalExpOne(P *G1Affine, Q *G2Affine, previous *GTEl) frontend.Variable {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)

	res := pr.IsEqual(t2, pr.One())
	return res
}

// AssertMillerLoopAndFinalExpIsOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and checks that the result lies in the
// same equivalence class as the reduced pairing purported to be 1. This check
// replaces the final exponentiation step in-circuit and follows Section 4 of
// [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr Pairing) AssertMillerLoopAndFinalExpIsOne(P *G1Affine, Q *G2Affine, previous *GTEl) {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)
	pr.AssertIsEqual(t2, pr.One())
}
