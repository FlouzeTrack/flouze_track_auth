/*
|--------------------------------------------------------------------------
| Routes file
|--------------------------------------------------------------------------
|
| The routes file is used for defining the HTTP routes.
|
*/
import router from '@adonisjs/core/services/router'
const RolesController = () => import('#controllers/roles_controller')
const UsersController = () => import('#controllers/users_controller')

router.get('/', async () => {
  return {
    hello: 'world',
  }
})

router
  .group(() => {
    router
      .group(() => {
        router.resource('roles', RolesController)
        router
          .group(() => {
            router.post('signin', [UsersController, 'signin'])
            router.post('signup', [UsersController, 'signup'])
            router.post('refreshToken', [UsersController, 'refreshToken'])
/*             router.post('forgotten', [UsersController, 'forgotten'])
            router.post('resend', [UsersController, 'resend'])
            router.post('activate', [UsersController, 'activate'])
            
            // Correct route for updating credentials with a PUT method
            router.put('users/:id/credential', [UsersController, 'credential'])
            
            router.get('me', [UsersController, 'me']) */
          })
          .prefix('auth')
      })
      .prefix('v1')
  })
  .prefix('api')
