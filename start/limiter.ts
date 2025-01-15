import limiter from '@adonisjs/limiter/services/main'

export const throttle = limiter.define('global', () => {
  return limiter
    .allowRequests(5)
    .every('1 minute')
    .limitExceeded((error) => {
      error.setStatus(400).setMessage('Rate limit attained. Try again later')
    })
    .blockFor('5 mins')
})
