package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/fieldextension"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/rs/zerolog"
	"golang.org/x/exp/constraints"
)

// Field holds the configuration for non-native field operations. The field
// parameters (modulus, number of limbs) is given by [FieldParams] type
// parameter. If [FieldParams.IsPrime] is true, then allows inverse and division
// operations.
type Field[T FieldParams] struct {
	// api is the native API
	api frontend.API
	// extensionApi is the extension API when we need to perform multiplication checks over the extension field
	extensionApi fieldextension.Field

	// fParams carries the ring parameters
	fParams staticFieldParams[T]

	// maxOf is the maximum overflow before the element must be reduced.
	maxOf     uint
	maxOfOnce sync.Once

	// constants for often used elements n, 0 and 1. Allocated only once
	nConstOnce     sync.Once
	nConst         *Element[T]
	nprevConstOnce sync.Once
	nprevConst     *Element[T]
	zeroConstOnce  sync.Once
	zeroConst      *Element[T]
	oneConstOnce   sync.Once
	oneConst       *Element[T]

	log zerolog.Logger

	constrainedLimbs map[[16]byte]struct{}
	checker          frontend.Rangechecker

	deferredChecks []deferredChecker
}

type ctxKey[T FieldParams] struct{}

// NewField returns an object to be used in-circuit to perform emulated
// arithmetic over the field defined by type parameter [FieldParams]. The
// operations on this type are defined on [Element].
func NewField[T FieldParams](native frontend.API) (*Field[T], error) {
	if storer, ok := native.(kvstore.Store); ok {
		ff := storer.GetKeyValue(ctxKey[T]{})
		if ff, ok := ff.(*Field[T]); ok {
			return ff, nil
		}
	}
	f := &Field[T]{
		api:              native,
		log:              logger.Logger(),
		constrainedLimbs: make(map[[16]byte]struct{}),
		checker:          rangecheck.New(native),
		fParams:          newStaticFieldParams[T](native.Compiler().Field()),
	}
	if smallfields.IsSmallField(native.Compiler().Field()) {
		f.log.Debug().Msg("using small native field, multiplication checks will be performed in extension field")
		extapi, err := fieldextension.NewExtension(native)
		if err != nil {
			return nil, fmt.Errorf("extension field: %w", err)
		}
		f.extensionApi = extapi
	}

	// ensure prime is correctly set
	if f.fParams.IsPrime() {
		if !f.fParams.Modulus().ProbablyPrime(20) {
			return nil, errors.New("invalid parametrization: modulus is not prime")
		}
	}

	if f.fParams.BitsPerLimb() < 3 {
		// even three is way too small, but it should probably work.
		return nil, errors.New("nbBits must be at least 3")
	}

	if f.fParams.Modulus().Cmp(big.NewInt(1)) < 1 {
		return nil, errors.New("n must be at least 2")
	}

	nbLimbs := (uint(f.fParams.Modulus().BitLen()) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	if nbLimbs != f.fParams.NbLimbs() {
		return nil, fmt.Errorf("nbLimbs mismatch got %d expected %d", f.fParams.NbLimbs(), nbLimbs)
	}

	if f.api == nil {
		return f, errors.New("missing api")
	}

	if uint(f.api.Compiler().FieldBitLen()) < 2*f.fParams.BitsPerLimb()+1 {
		return nil, fmt.Errorf("elements with limb length %d does not fit into scalar field", f.fParams.BitsPerLimb())
	}

	native.Compiler().Defer(f.performDeferredChecks)
	if storer, ok := native.(kvstore.Store); ok {
		storer.SetKeyValue(ctxKey[T]{}, f)
	}
	return f, nil
}

// NewElement builds a new Element[T] from input v.
//   - if v is a Element[T] or *Element[T] it clones it
//   - if v is a constant this is equivalent to calling emulated.ValueOf[T]
//   - if this methods interprets v as being the limbs (frontend.Variable or []frontend.Variable),
//     it constructs a new Element[T] with v as limbs and constraints the limbs to the parameters
//     of the Field[T].
func (f *Field[T]) NewElement(v interface{}) *Element[T] {
	if e, ok := v.(Element[T]); ok {
		return e.copy()
	}
	if e, ok := v.(*Element[T]); ok {
		return e.copy()
	}
	if frontend.IsCanonical(v) {
		return f.packLimbs([]frontend.Variable{v}, true)
	}
	if e, ok := v.([]frontend.Variable); ok {
		return f.packLimbs(e, true)
	}
	// the input was not a variable, so it must be a constant. Create a new
	// element from it while setting isWitness flag to false. This ensures that
	// we use the minimal number of limbs necessary.
	c := newConstElement[T](f.api.Compiler().Field(), v, false)
	return c
}

// Zero returns zero as a constant.
func (f *Field[T]) Zero() *Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = f.newInternalElement([]frontend.Variable{}, 0)
	})
	return f.zeroConst
}

// One returns one as a constant.
func (f *Field[T]) One() *Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = f.newInternalElement([]frontend.Variable{1}, 0)
	})
	return f.oneConst
}

// Modulus returns the modulus of the emulated ring as a constant.
func (f *Field[T]) Modulus() *Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = newConstElement[T](f.api.Compiler().Field(), f.fParams.Modulus(), false)
	})
	return f.nConst
}

// modulusPrev returns modulus-1 as a constant.
func (f *Field[T]) modulusPrev() *Element[T] {
	f.nprevConstOnce.Do(func() {
		f.nprevConst = newConstElement[T](f.api.Compiler().Field(), new(big.Int).Sub(f.fParams.Modulus(), big.NewInt(1)), false)
	})
	return f.nprevConst
}

// packLimbs returns an element from the given limbs.
// If strict is true, the most significant limb will be constrained to have width of the most
// significant limb of the modulus, which may have less bits than the other limbs. In which case,
// less constraints will be generated.
// If strict is false, each limbs is constrained to have width as defined by field parameter.
func (f *Field[T]) packLimbs(limbs []frontend.Variable, strict bool) *Element[T] {
	e := f.newInternalElement(limbs, 0)
	f.enforceWidth(e, strict)
	return e
}

func (f *Field[T]) enforceWidthConditional(a *Element[T]) (didConstrain bool) {
	if a == nil {
		// for some reason called on nil
		return false
	}
	// ensure that when the element is defined in-circuit with [ValueOf] method
	// (as a constant), then we decompose it into limbs. When [ValueOf] is called
	// for a witness assignment, then [Element.Initialize] is already called at
	// witness parsing time. In that case, the below operation is no-op.
	a.Initialize(f.api.Compiler().Field())
	if a.internal {
		// internal elements are already constrained in the method which returned it
		return false
	}
	if _, isConst := f.constantValue(a); isConst {
		// enforce constant element limbs not to be large.
		for i := range a.Limbs {
			val := utils.FromInterface(a.Limbs[i])
			if val.BitLen() > int(f.fParams.BitsPerLimb()) {
				panic("constant element limb wider than emulated parameter")
			}
		}
		// constant values are constant
		return false
	}
	for i := range a.Limbs {
		if !frontend.IsCanonical(a.Limbs[i]) {
			// this is not a canonical variable, nor a constant. This may happen
			// when some limbs are constant and some variables. Or if we are
			// running in a test engine. In either case, we must check that if
			// this limb is a [*big.Int] that its bitwidth is less than the
			// NbBits.
			val := utils.FromInterface(a.Limbs[i])
			if val.BitLen() > int(f.fParams.BitsPerLimb()) {
				panic("non-canonical integer limb wider than emulated parameter")
			}
			continue
		}
		if vv, ok := a.Limbs[i].(interface{ HashCode() [16]byte }); ok {
			// okay, this is a canonical variable and it has a hashcode. We use
			// it to see if the limb is already constrained.
			h := vv.HashCode()
			if _, ok := f.constrainedLimbs[h]; !ok {
				// we found a limb which hasn't yet been constrained. This means
				// that we should enforce width for the whole element. But we
				// still iterate over all limbs just to mark them in the table.
				didConstrain = true
				f.constrainedLimbs[h] = struct{}{}
			}
		} else {
			// we have no way of knowing if the limb has been constrained. To be
			// on the safe side constrain the whole element again.
			didConstrain = true
		}
	}
	if didConstrain {
		f.enforceWidth(a, true)
	}
	return
}

func (f *Field[T]) constantValue(v *Element[T]) (*big.Int, bool) {
	// this case happens when we have called [ValueOf] inside a circuit as
	// [Element.Initialize] has not been called (Limbs are nil). In this case,
	// we can directly use the witness value as the constant value.
	if v.Limbs == nil && v.witnessValue != nil {
		return new(big.Int).Set(v.witnessValue), true
	}

	// otherwise - it may happen that the user has manually constructed [Element] from constant limbs.
	// In this case, we can recompose the constant value from the limbs.
	var ok bool

	constLimbs := make([]*big.Int, len(v.Limbs))
	for i, l := range v.Limbs {
		// for each limb we get it's constant value if we can, or fail.
		if constLimbs[i], ok = f.api.ConstantValue(l); !ok {
			return nil, false
		}
	}

	res := new(big.Int)
	if err := limbs.Recompose(constLimbs, f.fParams.BitsPerLimb(), res); err != nil {
		f.log.Error().Err(err).Msg("recomposing constant")
		return nil, false
	}
	return res, true
}

// maxOverflow returns the maximal possible overflow for the element. If the
// overflow of the next operation exceeds the value returned by this method,
// then the limbs may overflow the native field.
func (f *Field[T]) maxOverflow() uint {
	f.maxOfOnce.Do(func() {
		f.maxOf = uint(f.api.Compiler().FieldBitLen()-2) - f.fParams.BitsPerLimb()
	})
	return f.maxOf
}

func max[T constraints.Ordered](a ...T) T {
	if len(a) == 0 {
		var f T
		return f
	}
	m := a[0]
	for _, v := range a {
		if v > m {
			m = v
		}
	}
	return m
}

func sum[T constraints.Ordered](a ...T) T {
	if len(a) == 0 {
		var f T
		return f
	}
	m := a[0]
	for _, v := range a[1:] {
		m += v
	}
	return m
}
