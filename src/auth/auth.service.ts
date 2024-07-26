import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Database connected');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.JWT_SECRET,
      });

      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token',
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;

    const user = await this.user.findUnique({
      where: { email },
    });

    if (user)
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'User already exists',
      });

    try {
      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });

      const { password: _, ...userData } = newUser;

      return {
        user: userData,
        token: await this.signJWT(userData),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        error: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    const user = await this.user.findUnique({
      where: { email },
    });

    if (!user)
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'Invalid credentials',
      });

    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid)
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'Invalid credentials',
      });

    const { password: _, ...userData } = user;

    return {
      user: userData,
      token: await this.signJWT(userData),
    };
  }
}
