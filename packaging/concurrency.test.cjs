const test = require('node:test')
const assert = require('node:assert/strict')
const { createSlots } = require('./concurrency.cjs')

test('lookup slots reject invalid limits', () => {
    for (const limit of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN]) {
        assert.throws(() => createSlots(limit), RangeError)
    }
})

test('lookup slots cap active work and release exactly once', () => {
    const slots = createSlots(2)
    const releaseFirst = slots.tryAcquire()
    const releaseSecond = slots.tryAcquire()

    assert.equal(typeof releaseFirst, 'function')
    assert.equal(typeof releaseSecond, 'function')
    assert.equal(slots.tryAcquire(), null)

    releaseFirst()
    releaseFirst()
    const releaseThird = slots.tryAcquire()
    assert.equal(typeof releaseThird, 'function')
    assert.equal(slots.tryAcquire(), null)

    releaseSecond()
    releaseThird()
    const releaseFourth = slots.tryAcquire()
    assert.equal(typeof releaseFourth, 'function')
    releaseFourth()
})
