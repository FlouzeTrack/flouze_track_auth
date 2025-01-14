import type { HttpContext } from '@adonisjs/core/http'
import Role from '#models/role'

export default class RolesController {
  /**
   * Display a list of resource
   */
  async index({ auth, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const roles = await Role.all()
      return roles
    } catch (error) {
      console.log(error)
      return response.status(404).send('Roles not found')
    }
  }

  /**
   * Display form to create a new record
   */
  async create({ auth, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      return response.send('roles.create')
    } catch (error) {
      console.log(error)
      return response.status(404).send('Failed to create a new record')
    }
  }

  /**
   * Handle form submission for the create action
   */
  async store({ auth, request, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const validatedData = request.only(['name'])
      if (validatedData.name !== '') {
        const role = Role.create(validatedData)
        return response.status(201).json({
          message: 'Role created successfully',
          data: role,
        })
      }
    } catch (error) {
      console.log(error)
      return response.status(400).json({
        message: 'Failed to create role',
      })
    }
  }

  /**
   * Show individual record
   */
  async show({ auth, params, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const role = await Role.findOrFail(params.id)
      return role
    } catch (error) {
      console.log(error)
      return response.status(404).send('Role not found')
    }
  }

  /**
   * Edit individual record
   */
  async edit({ auth, params, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const role = await Role.findOrFail(params.id)
      return params.render('roles.edit', { role })
    } catch (error) {
      console.log(error)
      return response.status(404).send('Role not found')
    }
  }

  /**
   * Handle form submission for the edit action
   */
  async update({ auth, params, request, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const validatedData = request.only(['name'])
      const role = await Role.findOrFail(params.id)
      role.merge(validatedData)
      await role.save()
      return role
    } catch (error) {
      console.log(error)
      return response.status(404).send('Role not found')
    }
  }

  /**
   * Delete record
   */
  async destroy({ auth, params, response }: HttpContext) {
    try {
      await auth.check()
      const user = auth.user
      if (user && !user.isAdmin()) {
        return response.status(403).json({
          message: 'Access denied. Only admins can view roles.',
        })
      }

      const role = await Role.findOrFail(params.id)
      await role.delete()
      return response.status(200).json({
        message: 'Role deleted successfully',
      })
    } catch (error) {
      console.log(error)
      return response.status(404).send('Role not found')
    }
  }
}
