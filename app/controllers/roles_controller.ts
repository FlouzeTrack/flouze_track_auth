import type { HttpContext } from '@adonisjs/core/http'

export default class RolesController {
  /**
   * Display a list of resource
   */
  async index({}: HttpContext) {
    return [
      {
        id: 1,
        username: 'virk',
      },
      {
        id: 2,
        username: 'romain',
      },
    ]
  }

  /**
   * Display form to create a new record
   */
  async create({}: HttpContext) {}

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
   * Edit individual record
   */
  async edit({ params }: HttpContext) {
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
