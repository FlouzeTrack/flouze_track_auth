import { BaseSeeder } from '@adonisjs/lucid/seeders'

import Role from '#models/role'

export default class RoleSeeder extends BaseSeeder {
  async run() {
    const uniqueKey = 'id'
    await Role.updateOrCreateMany(uniqueKey, [
      {
        id: 1,
        name: 'user',
      },
      {
        id: 2,
        name: 'admin',
      },
    ])
  }
}
