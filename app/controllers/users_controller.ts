import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import mail from '@adonisjs/mail/services/main'
import RefreshToken from '#models/refresh_token'
import hash from '@adonisjs/core/services/hash'
import { JwtGuard } from '../auth/guards/jwt.js'
import { createUserSchema } from '#validators/create_user'
import env from '#start/env'
import { DateTime } from 'luxon'

export default class UsersController {
  public async signup({ request, response }: HttpContext) {
    try {
      const data = request.all() // Récupérer toutes les données de la requête

      // Validation des données
      const payload = await createUserSchema.validate(data)

      // Déstructuration des données validées
      const { email, password } = payload
      const roleId = 1 // Role par défaut

      // Vérifier si l'email est déjà utilisé
      const existingUser = await User.query().where('email', email).first()

      if (existingUser) {
        return response.status(400).send({ error: 'Email already in use' })
      }

      // Créer le nouvel utilisateur avec le rôle par défaut
      const user = new User()
      user.email = email
      user.password = password
      user.role_id = roleId

      await user.save()

      return response.status(201).send({
        success: true,
      })
    } catch (error) {
      return response.status(400).json({
        error: error.message || 'Unable to create user',
      })
    }
  }

  // Connexion de l'utilisateur
  public async signin({ request, response, auth }: HttpContext) {
    try {
      const { email, password } = request.all()

      // Vérifier si l'utilisateur existe
      const user = await User.query().where('email', email).first()

      if (!user) {
        return response.status(401).send({ error: 'Invalid credentials' })
      }

      // Vérifier si le compte est verrouillé
      if (
        user.locked_until &&
        DateTime.fromISO(user.locked_until.toString()).diffNow().milliseconds > 0
      ) {
        return response
          .status(403)
          .send({ error: 'Account is temporarily locked. Please try again later.' })
      }

      // Vérifier si le mot de passe est valide
      const isValid = await hash.verify(user.password, password)

      if (!isValid) {
        // Incrémenter les tentatives échouées
        user.failed_attempts += 1

        // Si le nombre de tentatives échouées dépasse le seuil, verrouiller le compte
        if (user.failed_attempts >= 5) {
          user.locked_until = DateTime.local().plus({ minutes: 15 }) // verrouille pendant 15 minutes
        }

        await user.save()

        return response.status(401).send({ error: 'Invalid credentials' })
      }

      // Réinitialiser les tentatives échouées en cas de succès
      user.failed_attempts = 0
      user.locked_until = null
      await user.save()

      // Générer l'accessToken
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      const { token } = await jwtGuard.generate(user)

      // Générer le refreshToken
      const { refreshToken } = await jwtGuard.generateRefreshToken(user)

      const hashedRefreshToken = await hash.make(refreshToken)

      await RefreshToken.create({
        userId: user.id,
        token: hashedRefreshToken,
      })

      // Retourner les tokens générés
      return response.status(201).send({
        accessToken: token,
        refreshToken, // Le refreshToken peut être retourné en clair
      })
    } catch (error) {
      return response.status(400).json({
        error: error.message || 'Unable to sign in',
      })
    }
  }

  public async refreshToken({ response, auth }: HttpContext) {
    try {
      // Décode le refreshToken pour obtenir l'id de l'utilisateur
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      const newTokens = await jwtGuard.verifyRefreshToken()

      // Retourner le nouveau refreshToken
      return response.ok(newTokens)
    } catch (error) {
      console.log('error', error.message)
      return response.unauthorized({ error: 'Unauthorized' })
    }
  }

  public async me({ auth, response }: HttpContext) {
    try {
      await auth.check()

      const authUser = auth.user as User
      if (!authUser) {
        return response.unauthorized({ error: 'Unauthorized' })
      }

      const user = await User.query().where('id', authUser.id).firstOrFail()

      return response.ok({
        id: user.id,
        email: user.email,
      })
    } catch (error) {
      return response.unauthorized({ error: 'Unauthorized' })
    }
  }

  public async authenticate({ auth, response }: HttpContext) {
    try {
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      const user = await jwtGuard.authenticate()

      return response.ok({
        id: user.id,
        email: user.email,
      })
    } catch (error) {
      return response.unauthorized({
        error: error.message || 'Unauthorized',
      })
    }
  }

  public async forgotten({ response }: HttpContext) {
    try {
      await mail.send((message) => {
        message
          .to('test@gmail.com')
          .from(env.get('SMTP_USERNAME'))
          .subject('Password Reset')
          .htmlView('emails/reset_password_html')
      })
      console.log('Password reset email sent')

      return response.status(200).send({ message: 'Password reset email sent' })
    } catch (error) {
      console.log('error', error)
      return response.status(400).json({
        error: 'Unable to send email',
        errorMsg: error,
      })
    }
  }

  public async activate({ response }: HttpContext) {
    try {
      await mail.send((message) => {
        message
          .to('test@gmail.com')
          .from(env.get('SMTP_USERNAME'))
          .subject('Email Validation')
          .htmlView('emails/verify_email_html')
      })
      console.log('Email validation sent')

      return response.status(200).send({ message: 'Email validation sent' })
    } catch (error) {
      console.log('error', error)
      return response.status(400).json({
        error: 'Unable to send email',
        errorMsg: error,
      })
    }
  }
}
