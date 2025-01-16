import { BaseSeeder } from '@adonisjs/lucid/seeders'

import User from '#models/user'

export default class UserSeeder extends BaseSeeder {
  async run() {
    const uniqueKey = 'email'
    await User.updateOrCreateMany(uniqueKey, [
      {
        email: 'flouze.track.hetic@gmail.com',
        password: 'Password1234?',
        activate: true,
        role_id: 1,
      },
    ])
  }
}
