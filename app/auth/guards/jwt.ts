import { symbols, errors } from '@adonisjs/auth'
import { AuthClientResponse, GuardContract } from '@adonisjs/auth/types'
import jwt from 'jsonwebtoken'
import type { HttpContext } from '@adonisjs/core/http'
import hash from '@adonisjs/core/services/hash'
import RefreshToken from '#models/refresh_token'

export type JwtGuardOptions = {
  secret: string
}

/**
 * The bridge between the User provider and the
 * Guard
 */
export type JwtGuardUser<RealUser> = {
  /**
   * Returns the unique ID of the user
   */
  getId(): string | number | BigInt

  /**
   * Returns the original user object
   */
  getOriginal(): RealUser
}

/**
 * The interface for the UserProvider accepted by the
 * JWT guard.
 */
export interface JwtUserProviderContract<RealUser> {
  /**
   * A property the guard implementation can use to infer
   * the data type of the actual user (aka RealUser)
   */
  [symbols.PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<JwtGuardUser<RealUser>>

  /**
   * Find a user by their id.
   */
  findById(identifier: string | number | BigInt): Promise<JwtGuardUser<RealUser> | null>
}

export class JwtGuard<UserProvider extends JwtUserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof symbols.PROVIDER_REAL_USER]>
{
  #ctx: HttpContext
  #userProvider: UserProvider
  #options: JwtGuardOptions

  constructor(ctx: HttpContext, userProvider: UserProvider, options: JwtGuardOptions) {
    this.#ctx = ctx
    this.#userProvider = userProvider
    this.#options = options
  }
  /**
   * A list of events and their types emitted by
   * the guard.
   */
  declare [symbols.GUARD_KNOWN_EVENTS]: {}

  /**
   * A unique name for the guard driver
   */
  driverName: 'jwt' = 'jwt'

  /**
   * A flag to know if the authentication was an attempt
   * during the current HTTP request
   */
  authenticationAttempted: boolean = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated: boolean = false

  /**
   * Reference to the currently authenticated user
   */
  user?: UserProvider[typeof symbols.PROVIDER_REAL_USER]

  /**
   * Generate a JWT token for a given user.
   */
  async generate(user: UserProvider[typeof symbols.PROVIDER_REAL_USER]) {
    const providerUser = await this.#userProvider.createUserForGuard(user)
    const token = jwt.sign(
      { userId: providerUser.getId() },
      this.#options.secret,
      { expiresIn: '30s' } // Ajoutez l'option expiresIn
    )

    return {
      type: 'bearer',
      token: token,
    }
  }

  /**
   * Authenticate the current HTTP request and return
   * the user instance if there is a valid JWT token
   * or throw an exception
   */
  async authenticate(): Promise<UserProvider[typeof symbols.PROVIDER_REAL_USER]> {
    /**
     * Avoid re-authentication when it has been done already
     * for the given request
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }
    this.authenticationAttempted = true

    console.log('Header', this.#ctx.request.header('authorization'))

    /**
     * Ensure the auth header exists
     */
    const authHeader = this.#ctx.request.header('authorization')
    if (!authHeader) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    console.log('authHeader', authHeader)
    /**
     * Split the header value and read the token from it
     */
    const [, token] = authHeader.split('Bearer ')
    if (!token) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    console.log('token', token)
    /**
     * Verify token
     */
    try {
      const payload = jwt.verify(token, this.#options.secret)
      if (typeof payload !== 'object' || !('userId' in payload)) {
        throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
          guardDriverName: this.driverName,
        })
      }
      console.log('payload', payload)

      /**
       * Fetch the user by user ID and save a reference to it
       */
      const providerUser = await this.#userProvider.findById(payload.userId)
      if (!providerUser) {
        throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
          guardDriverName: this.driverName,
        })
      }

      console.log('providerUser', providerUser)

      this.user = providerUser.getOriginal()
      return this.getUserOrFail()
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw new errors.E_UNAUTHORIZED_ACCESS('Token has expired', {
          guardDriverName: this.driverName,
        })
      }
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }
  }

  /**
   * Same as authenticate, but does not throw an exception
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch {
      return false
    }
  }

  /**
   * Returns the authenticated user or throws an error
   */
  getUserOrFail(): UserProvider[typeof symbols.PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new errors.E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  async getToken(): Promise<string> {
    try {
      const authHeader = this.#ctx.request.header('authorization')
      if (!authHeader) {
        throw new Error('No authorization header found.')
      }

      const [, token] = authHeader.split('Bearer ')
      if (!token) {
        throw new Error('No token found.')
      }

      return token
    } catch (error) {
      throw new Error(error.message || 'No token found.')
    }
  }

  /**
   * This method is called by Japa during testing when "loginAs"
   * method is used to login the user.
   */
  async authenticateAsClient(
    user: UserProvider[typeof symbols.PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const token = await this.generate(user)
    return {
      headers: {
        authorization: `Bearer ${token.token}`,
      },
    }
  }

  /**
   * Verify and refresh the refresh token.
   *
   * @param refreshToken
   * @param userId
   * @returns A new refreshToken if the old one is valid.
   */
  public async verifyRefreshToken() {
    try {
      // get user from the guard
      const user = await this.authenticate()
      console.log('user', user)
      const providerUser = await this.#userProvider.createUserForGuard(user)
      const userId = providerUser.getId() as string

      // get the refreshToken from the request
      const refreshToken = await this.getToken()

      // Rechercher le refreshToken dans la base de données pour l'utilisateur
      const storedRefreshTokens = await RefreshToken.query().where('userId', userId)

      if (!storedRefreshTokens.length) {
        throw new Error('No refresh token found for this user.')
      }

      console.log('storedRefreshTokens', storedRefreshTokens)
      for (const storedRefreshToken of storedRefreshTokens) {
        // Comparer le refreshToken envoyé avec celui stocké dans la BDD
        const isValid = await hash.verify(storedRefreshToken.token, refreshToken)

        console.log('isValid', isValid)
        if (isValid) {
          // Supprimer l'ancien refreshToken de la base de données
          await storedRefreshToken.delete()

          // Générer un nouveau Token
          const { token } = await this.generate(user)

          // Générer un nouveau refreshToken
          const { refreshToken: newRefreshToken, hashedRefreshToken: newHashedRefreshToken } =
            await this.generateRefreshToken(user)

          // Enregistrer le nouveau refreshToken dans la base de données
          await RefreshToken.create({
            userId: userId,
            token: newHashedRefreshToken,
          })

          // Retourner le nouveau refreshToken
          return {
            accessToken: token,
            refreshToken: newRefreshToken,
          }
        }
      }
      throw new Error('Invalid refresh token.')
    } catch (error) {
      throw new Error(error.message || 'Unable to refresh token.')
    }
  }

  /**
   * Generate a refresh token for a given user.
   * The token is hashed before saving it in the database.
   */
  public async generateRefreshToken(user: UserProvider[typeof symbols.PROVIDER_REAL_USER]) {
    const providerUser = await this.#userProvider.createUserForGuard(user)

    // Génération du refresh token
    const refreshToken = jwt.sign(
      { userId: providerUser.getId() },
      this.#options.secret,
      { expiresIn: '7d' } // Par exemple, une durée de validité de 7 jours
    )

    // Hachage du token avant de le sauvegarder
    const hashedRefreshToken = await hash.make(refreshToken)

    return {
      refreshToken,
      hashedRefreshToken, // À enregistrer dans la base de données
    }
  }

  /**
   * Generate a temporary JWT token valid for 5 minutes.
   */
  public async generateTemporaryJwt(user: UserProvider[typeof symbols.PROVIDER_REAL_USER]) {
    const providerUser = await this.#userProvider.createUserForGuard(user)

    const token = jwt.sign(
      { userId: providerUser.getId() },
      this.#options.secret,
      { expiresIn: '5m' } // Durée de validité de 5 minutes
    )

    return {
      type: 'bearer',
      token: token,
    }
  }
}
