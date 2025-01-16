import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'users'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.uuid('id').primary()
      table.string('email', 254).notNullable().unique()
      table.string('password').notNullable()
      table.integer('role_id').notNullable().unsigned().references('id').inTable('roles')
      table.integer('failed_attempts').defaultTo(0) 
      table.timestamp('locked_until').nullable() 
      table.boolean('activate').defaultTo(false) 
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
