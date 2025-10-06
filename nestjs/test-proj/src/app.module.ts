import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PetsModule } from './pets/pets.module';
import { DogsModule } from './dogs/dogs.module';

@Module({
  imports: [PetsModule, DogsModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
