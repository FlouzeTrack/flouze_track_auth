import { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import Role from '#models/role'
import hash from '@adonisjs/core/services/hash'

export default class UsersController {
  public async signup({ request, response }: HttpContext) {
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

    const user = await User.create({
      email,
      password: password,
      role_id
    })
  
    return response.status(201).send(user)
  }

  // Connexion de l'utilisateur
  public async signin({ request, response }: HttpContext) {
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
  
    return response.status(200).send({ message: 'Signed in successfully' })
  }
  
  // Récupérer les informations de l'utilisateur connecté
  public async me({ auth, response }: HttpContext) {
    const user = auth.user
    if (!user) {
      return response.status(401).send({ error: 'Unauthorized' })
    }

    await user.load('role')
    return response.status(200).send(user)
  }

  // Oublier le mot de passe (exemple, à adapter)
  public async forgotten({ request, response }: HttpContext) {
    const { email } = request.all()
    const user = await User.query().where('email', email).first()

    if (!user) {
      return response.status(404).send({ error: 'User not found' })
    }

    // Logique pour réinitialiser le mot de passe (envoi d'email, etc.)
    return response.status(200).send({ message: 'Password reset email sent' })
  }

  // Renvoi de l'activation (exemple)
  public async resend({ request, response }: HttpContext) {
    const { email } = request.all()
    const user = await User.query().where('email', email).first()

    if (!user) {
      return response.status(404).send({ error: 'User not found' })
    }

    // Logique de renvoi de l'activation (exemple)
    return response.status(200).send({ message: 'Activation email resent' })
  }

  // Activer un compte (exemple)
  public async activate({ request, response }: HttpContext) {
    /* const { token } = request.all() */

    // Logique d'activation avec le token
    return response.status(200).send({ message: 'Account activated successfully' })
  }

  // Modifier les informations d'identification de l'utilisateur (exemple)
  public async credential({ request, response }: HttpContext) {
    const { password } = request.all()
    const userId = request.param('id')  // Récupère l'ID de l'utilisateur dans l'URL
  
    const user = await User.findOrFail(userId)
  
    user.password = await hash.make(password)
    await user.save()
  
    return response.status(200).send({ message: 'Credentials updated successfully' })
  }
  
}
