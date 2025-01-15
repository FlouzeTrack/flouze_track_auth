import { BaseSchema } from '@adonisjs/lucid/schema'

export default class extends BaseSchema {
  protected tableName = 'refresh_tokens'

  async up() {
    this.schema.createTable(this.tableName, (table) => {
      table.increments('id') // Identifiant unique
      table.string('user_id').references('id').inTable('users').onDelete('CASCADE') // Relation avec l'utilisateur
      table.string('token', 255).notNullable() // Le token haché
      table.timestamps(true, true) // created_at et updated_at
    })
  }

  async down() {
    this.schema.dropTable(this.tableName)
  }
}
