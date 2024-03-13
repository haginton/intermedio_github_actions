package com.previo7.previo7s.controller.user;

import com.previo7.previo7s.dto.UserDto;
import com.previo7.previo7s.dto.UserResponseDto;
import com.previo7.previo7s.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.NoSuchElementException;

import static com.previo7.previo7s.utils.Constants.ADMIN_ROLE;

@RestController
@RequestMapping("/v1/user")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
        //loadSampleUsers();
    }

    public void loadSampleUsers() {
        LocalDate fecha = LocalDate.of(2024, 2, 22);
        UserDto userEntity = new UserDto("Ada", " Lovelace", fecha, "ada@mail.com", "passw0rd");
        userService.createUser(userEntity);
        UserDto adminUserEntity = new UserDto("Ada", "Admin", fecha, "admin@mail.com", "passw0rd");
        UserResponseDto userCreated = userService.createUser(adminUserEntity);
    }

    @Operation(summary = "Consult all user", description = "In this controller you can consult all the users")
    //@SecurityRequirement(name = "Bearer Authentication")
    @GetMapping
    public ResponseEntity<List<UserResponseDto>> getAllUsers(){
        try{
            List<UserResponseDto> usersResponseDto = userService.getAllUsers();
            if (usersResponseDto.isEmpty()){
                return new ResponseEntity<>(usersResponseDto, HttpStatus.NO_CONTENT);
            }
            return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
        }catch (RuntimeException e){
            return new ResponseEntity("An error has occurred while retrieving users", HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponseDto> findUserById(@PathVariable String id){
        try {
            return new ResponseEntity<>(userService.findUserById(id), HttpStatus.OK);
        }catch (NoSuchElementException e){
            return new ResponseEntity("The user " +  id + " doesn't exist in the database", HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping
    public ResponseEntity<UserResponseDto> createUser(@RequestBody UserDto userDto){
        try{
            return new ResponseEntity<>(userService.createUser(userDto), HttpStatus.CREATED);
        }catch (RuntimeException e){
            return new ResponseEntity("An error has occurred while retrieving users", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RolesAllowed(ADMIN_ROLE)
    @PostMapping("/createAdmin")
    public ResponseEntity<UserResponseDto> createUserAdmin(@RequestBody UserDto userDto){
        return new ResponseEntity<>(userService.createUserAdmin(userDto), HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Boolean> updateUser(@PathVariable String id, @RequestBody UserDto userDto){
        try {
            Boolean isUpdated = userService.updateUser(id, userDto);
            if (isUpdated){
                return new ResponseEntity(true, HttpStatus.OK);
            }else {
                return new ResponseEntity(false, HttpStatus.NOT_FOUND);
            }

        }catch (NoSuchElementException e){
            return new ResponseEntity("The user " + id + " doesn't exist in the data base", HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Boolean> deleteUser(@PathVariable String id){
        try {
            Boolean isDeleted = userService.deleteUser(id);
            if (isDeleted){
                return new ResponseEntity(true, HttpStatus.OK);
            }else {
                return new ResponseEntity(false, HttpStatus.NOT_FOUND);
            }

        }catch (NoSuchElementException e){
            return new ResponseEntity("The user " + id + " doesn't exist in the data base", HttpStatus.NOT_FOUND);
        }
    }
}
