import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import RefreshToken from '#models/refresh_token'
import hash from '@adonisjs/core/services/hash'
import { JwtGuard } from '../auth/guards/jwt.js'

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

      // Générer l'accessToken
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      const { token } = await jwtGuard.generate(user)

      // Générer le refreshToken
      const { refreshToken } = await jwtGuard.generateRefreshToken(user)

      const hashedRefreshToken = await hash.make(refreshToken)
      

      await RefreshToken.create({
        userId: user.id,  // user.id devrait être une chaîne (string), assure-toi qu'il est du bon type
        token: hashedRefreshToken,
      })
      

      // Retourner les tokens générés
      return response.status(201).send({
        accessToken: token,
        refreshToken, // Le refreshToken peut être retourné en clair
      })
    } catch (error) {
      return response.status(400).json({
        error: error.message || 'Unable to create user',
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
    try {
      // Vérifier que l'utilisateur est authentifié
      await auth.check()
  
      const authUser = auth.user as User
      if (!authUser) {
        return response.unauthorized({ error: 'User not found' }) // Il faudra deconnecter le user en front 
      }
  
      // Extraire le refreshToken de l'en-tête Authorization
      const refreshToken = request.header('Authorization')?.replace('Bearer ', '')
      if (!refreshToken) {
        return response.badRequest({ error: 'Refresh token not provided' })
      }
  
      // Utilisation de JwtGuard pour vérifier le refreshToken
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
      
      // Appeler la méthode verifyRefreshToken du JwtGuard pour vérifier et générer un nouveau refreshToken
      const result = await jwtGuard.verifyRefreshToken(refreshToken, authUser)
  
      if (result.error) {
        return response.badRequest({ error: result.error })
      }
  
      // Retourner le nouveau refreshToken
      return response.ok(result)
    } catch (error) {
      return response.unauthorized({ error: 'Unauthorized' })
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


  public async authenticate({ auth, response }: HttpContext) {
    try {
      const jwtGuard = auth.use('jwt') as JwtGuard<any>;
      const user = await jwtGuard.authenticate();

      return response.ok({
        id: user.id,
        email: user.email,
      });
    } catch (error) {
      return response.unauthorized({
        error: error.message || 'Unauthorized',
      });
    }
  }
}
