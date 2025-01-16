import hash from '@adonisjs/core/services/hash'
import { compose } from '@adonisjs/core/helpers'
import { BaseModel, beforeCreate, belongsTo, column } from '@adonisjs/lucid/orm'
import { withAuthFinder } from '@adonisjs/auth/mixins/lucid'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'
import Role from './role.js'
import type { BelongsTo } from '@adonisjs/lucid/types/relations'
import { v4 as uuidv4 } from 'uuid'
import { DateTime } from 'luxon'

const AuthFinder = withAuthFinder(() => hash.use('scrypt'), {
  uids: ['email'],
  passwordColumnName: 'password',
})

export default class User extends compose(BaseModel, AuthFinder) {
  @column({ isPrimary: true })
  declare id: string

  @column()
  declare email: string

  @column()
  declare password: string

  @column()
  declare role_id: number

  @column()
  declare failed_attempts: number // Nouveau champ : tentatives échouées

  @column.dateTime()
  declare locked_until: DateTime | null // Nouveau champ : date de verrouillage

  @column()
  declare activate: boolean // Nouveau champ : activation du compte

  @belongsTo(() => Role)
  declare role: BelongsTo<typeof Role>

  @beforeCreate()
  public static assignUuid(model: User) {
    model.id = uuidv4() // Génère un UUID avant l'insertion
  }

  static accessTokens = DbAccessTokensProvider.forModel(User)

  public isAdmin(): boolean {
    return this.role_id === 1
  }
}
