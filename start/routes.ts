/*
|--------------------------------------------------------------------------
| Routes file
|--------------------------------------------------------------------------
|
| The routes file is used for defining the HTTP routes.
|
*/
import router from '@adonisjs/core/services/router'
import { throttle } from './limiter.js'
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
            router.post('refresh', [UsersController, 'refreshToken'])
            router.get('me', [UsersController, 'me'])
            router.get('authenticate', [UsersController, 'authenticate'])
            router.post('forgotten', [UsersController, 'forgotten'])
            router.post('activate', [UsersController, 'activate'])
            /* router.post('resend', [UsersController, 'resend'])
            
            // Correct route for updating credentials with a PUT method
            router.put('users/:id/credential', [UsersController, 'credential'])
            
            router.get('me', [UsersController, 'me']) */
          })
          .prefix('auth')
      })
      .prefix('v1')
  })
  .use(throttle)
  .prefix('api')
