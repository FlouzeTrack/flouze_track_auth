import type { HttpContext } from '@adonisjs/core/http'

export default class UsersController {
  /**
   * Display a list of resource
   */
  async index({}: HttpContext) {}

  /**
   * Display form to create a new record
   */
  async create({}: HttpContext) {}

  /**
   * Display form to signin
   */
  async signin({}: HttpContext) {
    return {
      message: 'signin',
    }
  }

  /**
   * Display form to signup
   */
  async signup({}: HttpContext) {
    return {
      message: 'signup',
    }
  }

  /**
   * Handle form submission for the create action
   */
  async store({ request }: HttpContext) {
    console.log(request)
  }

  /**
   * Show individual record
   */
  async show({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Show me
   */
  async me({ params }: HttpContext) {
    console.log(params)
    return {
      message: 'me',
    }
  }

  /**
   * Edit individual record
   */
  async edit({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Edit individual crediential
   */
  async credential({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Send email password change
   */
  async forgotten({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Resend email password change
   */
  async resend({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Activate account
   */
  async activate({ params }: HttpContext) {
    console.log(params)
  }

  /**
   * Handle form submission for the edit action
   */
  async update({ params, request }: HttpContext) {
    console.log(params, request)
  }

  /**
   * Delete record
   */
  async destroy({ params }: HttpContext) {
    console.log(params)
  }
}
