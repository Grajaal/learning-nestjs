import {
  Controller,
  Post,
  UseGuards,
  Req,
  Body,
  Res,
  Get
} from '@nestjs/common'
import { AuthService } from './auth.service'
import { LocalAuthGuard } from './guards/local-auth.guard'
import { Request, Response } from 'express'
import { RegisterDto } from './dto/register.dto'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { JwtRequest } from './interfaces/jwt-payload.interface'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() userData: RegisterDto) {
    return this.authService.register(userData)
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  login(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const { token } = this.authService.login(req.user)

    const isProduction = process.env.NODE_ENV === 'production'

    // Intentar establecer cookie (puede que Railway la bloquee)
    res.cookie('jwt', token, {
      httpOnly: true,
      maxAge: 14400000, // 4 hours
      secure: true,
      sameSite: isProduction ? 'none' : 'lax',
      path: '/'
    })

    // Debug headers
    res.setHeader('X-Cookie-Debug', 'cookie-set')
    res.setHeader('X-Is-Secure', 'true')
    res.setHeader('X-Same-Site', isProduction ? 'none' : 'lax')

    // SOLUCIÓN ALTERNATIVA: Enviar token también en el response
    return {
      user: req.user,
      token: token // ✅ Enviamos el token para que el frontend lo maneje
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('validate')
  validate(@Req() req: JwtRequest) {
    return {
      isAuthenticated: true,
      user: req.user
    }
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const isProduction = process.env.NODE_ENV === 'production'

    res.clearCookie('jwt', {
      httpOnly: true,
      secure: true, // Siempre true para production cross-origin
      sameSite: isProduction ? 'none' : 'lax',
      path: '/'
    })
    return { message: 'Logout successful' }
  }
}
