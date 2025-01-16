import vine from '@vinejs/vine'

// Définir un type plus flexible pour `messages`
interface Messages {
  [key: string]: string
}

export const createUserSchema = vine.compile(
  vine.object({
    email: vine.string().email(),
    password: vine
      .string()
      .minLength(8)
      .maxLength(32)
      .regex(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  })
)

export const resetPasswordSchema = vine.compile(
  vine.object({
    password: vine
      .string()
      .minLength(8)
      .maxLength(32)
      .regex(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
  })
)

export const messages: Messages = {
  'email.email': 'Veuillez fournir une adresse email valide.',
  'password.minLength': 'Le mot de passe doit contenir au moins 8 caractères.',
  'password.maxLength': 'Le mot de passe ne peut pas dépasser 32 caractères.',
  'password.regex':
    'Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial.',
  'role_id.number': 'Le rôle doit être un nombre valide.',
}
