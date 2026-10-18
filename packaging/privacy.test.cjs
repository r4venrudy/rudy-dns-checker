const test = require('node:test')
const assert = require('node:assert/strict')
const { privateByDefault } = require('./privacy.cjs')

test('domain reports are private unless the user opts into a public reply', () => {
    assert.equal(privateByDefault(null), true)
    assert.equal(privateByDefault(undefined), true)
    assert.equal(privateByDefault(true), true)
    assert.equal(privateByDefault(false), false)
})
