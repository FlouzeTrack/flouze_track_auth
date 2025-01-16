import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import mail from '@adonisjs/mail/services/main'
import RefreshToken from '#models/refresh_token'
import hash from '@adonisjs/core/services/hash'
import { JwtGuard } from '../auth/guards/jwt.js'
import { createUserSchema, resetPasswordSchema } from '#validators/create_user'
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

  public async forgotten({ request, response, auth }: HttpContext) {
    try {
      const { email } = request.all()
  
      // Log l'email reçu
      console.log('Email received for password reset:', email)
  
      // Vérifier si l'utilisateur existe
      const user = await User.query().where('email', email).first()
  
      // Log l'utilisateur trouvé
      if (!user) {
        await this.simulateProcessingDelay()
        console.log('User not found:', email)
        return response.status(200).send({ message: 'If the email exists, a reset email has been sent.' })
      } else {
        console.log('User found:', user.id)
      }
  
      // Générer le JWT temporaire
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      console.log('Generating temporary JWT for user ID:', user.id)
  
      const { token } = await jwtGuard.generateTemporaryJwt(user)
      console.log('Password reset token generated:', token)
  
      // Envoyer l'email
      const resetUrl = `http://localhost:5173/reset-password/${token}`
      console.log('Sending reset email to:', user.email)
  
      await mail.send((message) => {
        message
          .to(user.email)
          .from(env.get('SMTP_USERNAME'))
          .subject('Reset Your Password')
          .htmlView('emails/reset_password_html', { resetUrl })
      })
      console.log('Password reset email sent successfully')
  
      return response.status(200).send({ message: 'If the email exists, a reset email has been sent.' })
  
    } catch (error) {
      // Log l'erreur complète avec le stack trace pour plus de détails
      console.error('Error generating password reset token:', error)
  
      return response.status(400).json({
        error: 'Unable to process your request at this time.',
        errorMsg: error.message,
        stack: error.stack,  // Inclure le stack trace pour faciliter le debug
      })
    }
  }
  
  
  /**
   * Simulate a delay to make the response time consistent
   * when the email does not exist.
   */
  private async simulateProcessingDelay() {
    return new Promise((resolve) => setTimeout(resolve, 500))
  }




  public async resetPassword({ request, response, auth }: HttpContext) {
    try {
      const { password } = request.all()
  
      // Validation du mot de passe
      const payload = await resetPasswordSchema.validate({ password })
  
      // Extraire le nouveau mot de passe validé
      const { password: newPassword } = payload
  
      // Utilisation du JWT pour obtenir l'utilisateur
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      const user = await jwtGuard.authenticate()
  
      if (!user) {
        return response.status(404).send({ error: 'User not found' })
      }
      // Mise à jour du mot de passe de l'utilisateur
      user.password = newPassword
      await user.save()
  
      return response.status(200).send({ success: true, message: 'Password updated successfully' })
    } catch (error) {
      return response.unauthorized({
        error: error.message || 'Unauthorized',
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
