import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import Role from '#models/role'
import hash from '@adonisjs/core/services/hash'
import { JwtGuard } from '../auth/guards/jwt.js'

export default class UsersController {
  public async signup({ request, response, auth }: HttpContext) {
    const { email, password, role_id } = request.all()
    
      // Vérifier si le rôle existe
      const role = await Role.find(role_id)
      if (!role) {
        return response.status(400).send({ error: 'Role not found' })
      }
    
      // Vérifier si l'email est déjà utilisé
      const existingUser = await User.query().where('email', email).first()
      if (existingUser) {
        return response.status(400).send({ error: 'Email already in use' })
      }
    
      // Créer un nouvel utilisateur avec un mot de passe hashé
      const user = new User()
      user.email = email
      user.password = password// Hash du mot de passe
      user.role_id = role_id
    
      await user.save()
    
      // Typage explicite du retour de auth.use('jwt')
      const jwtGuard = auth.use('jwt') as JwtGuard<any>
    
      // Générez un JWT pour l'utilisateur après l'inscription
      return response.status(201).send(await jwtGuard.generate(user))
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
  

}
