import {
  ArrayMinSize,
  IsArray,
  IsString,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class LinkRequirementMappingDto {
  @ApiProperty({ description: 'Requirement ID' })
  @IsString()
  requirementId: string;

  @ApiProperty({ description: 'Framework instance ID' })
  @IsString()
  frameworkInstanceId: string;
}

export class LinkRequirementsToControlDto {
  @ApiProperty({
    description: 'Requirement + framework instance pairs to link',
    type: [LinkRequirementMappingDto],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => LinkRequirementMappingDto)
  requirements: LinkRequirementMappingDto[];
}
