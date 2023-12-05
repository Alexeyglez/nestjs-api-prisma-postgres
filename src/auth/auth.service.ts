import { Body, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { ConfigService} from '@nestjs/config';
import {JwtService} from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}

    async signin(authDto: AuthDto){
        const user = await this.prisma.user.findUnique({
            where: {
                email: authDto.email
            }
        });
        if(!user) {
            throw new ForbiddenException('Credentials incorrect')
        }
        //compare de password 
        const isCorrectPassword = await argon.verify(user.hash, authDto.password);
        if(!isCorrectPassword) {
            throw new ForbiddenException('Inavalid credentials');
        }
        
        return this.signToken(user.id, user.email);
    }

    async signup(authDto: AuthDto){
        const hash = await argon.hash(authDto.password);
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: authDto.email,
                    hash
                }
            });
            
            return this.signToken(user.id, user.email);
        } catch (error) {            
            if (error.code === 'P2002') {
                  throw new ForbiddenException(
                    'Credentials taken',
                  );
                }                  
        }
        
    }

    async signToken(userId: number, email: string): Promise<{access_token: string}>{
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET');

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
         });

        return { access_token: token };
    }
}
