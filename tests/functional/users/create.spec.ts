import User from '#models/user'
import { test } from '@japa/runner'
import hash from '@adonisjs/core/services/hash'
import Role from '#models/role'

test.group('creating user', (group) => {
  group.each.setup(async () => {
    console.log('runs before every test')
  })

  group.each.teardown(async () => {
    console.log('runs after every test')
  })

  group.setup(async () => {
    console.log('runs once before all the tests')
  })

  group.teardown(async () => {
    console.log('runs once after all the tests')
  })
  test('hashes user password', async ({ assert }) => {
    const user = new User()
    user.password = 'secret'
    user.email = 'test@gmail.com'
    user.role_id = 1

    await user.save()

    assert.isTrue(hash.isValidHash(user.password))
    assert.isTrue(await hash.verify(user.password, 'secret'))
  })
})
