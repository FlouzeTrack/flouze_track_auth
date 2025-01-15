import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import mail from '@adonisjs/mail/services/main'

import hash from '@adonisjs/core/services/hash'
import { JwtGuard } from '../auth/guards/jwt.js'
import env from '#start/env'

export default class UsersController {
  public async signup({ request, response, auth }: HttpContext) {
    // Destructure avec une valeur par défaut pour role_id
    const { email, password, roleId = 1 } = request.all()

    try {
      // Vérifier si l'email est déjà utilisé
      const existingUser = await User.query().where('email', email).first()

      if (existingUser) {
        return response.status(400).send({ error: 'Email already in use' })
      }

      // Créer le nouvel utilisateur avec le rôle par défaut
      const user = new User()
      user.email = email
      user.password = password
      user.role_id = roleId // Sera 1 par défaut si non spécifié

      await user.save()

      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      return response.status(201).send(await jwtGuard.generate(user))
    } catch (error) {
      return response.status(400).json({
        error: 'Unable to create user',
      })
    }
  }

  // Connexion de l'utilisateur
  public async signin({ request, response, auth }: HttpContext) {
    const { email, password } = request.all()

    // Vérifier si l'utilisateur existe
    const user = await User.query().where('email', email).first()
    if (!user) {
      return response.status(404).send({ error: 'User not found' })
    }

    // Vérifier si le mot de passe est valide
    const isValid = await hash.verify(user.password, password)

    if (!isValid) {
      return response.status(401).send({ error: 'Invalid credentials' })
    }

    // Typage explicite du retour de auth.use('jwt')
    const jwtGuard = auth.use('jwt') as JwtGuard<any>

    // Générez un JWT pour l'utilisateur après la connexion
    return response.status(200).send(await jwtGuard.generate(user))
  }

  public async refreshToken({ request, response, auth }: HttpContext) {
    const { refresh_token } = request.all()

    // Vérifier si le refresh token est fourni
    if (!refresh_token) {
      return response.status(400).send({ error: 'Refresh token is required' })
    }

    try {
      // Typage explicite du retour de auth.use('jwt')
      const jwtGuard = auth.use('jwt') as JwtGuard<any>

      // Vérification de la validité du refresh token
      const decoded = jwtGuard.verifyRefreshToken(refresh_token)

      if (!decoded) {
        return response.status(401).send({ error: 'Invalid refresh token' })
      }

      // Utiliser l'ID du payload pour retrouver l'utilisateur
      const user = await User.find(decoded.userId)
      if (!user) {
        return response.status(404).send({ error: 'User not found' })
      }

      // Générer un nouveau JWT pour l'utilisateur
      return response.status(200).send(await jwtGuard.generate(user))
    } catch (err) {
      return response.status(401).send({ error: 'Invalid or expired refresh token' })
    }
  }

  public async me({ auth, response }: HttpContext) {
    try {
      await auth.check()

      const authUser = auth.user as User
      if (!authUser) {
        return response.unauthorized({ error: 'User not found' })
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

  public async forgotten({ request, response }: HttpContext) {
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

  public async activate({ request, response }: HttpContext) {
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
