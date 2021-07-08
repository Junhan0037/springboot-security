package com.springcoresecurity.controller.user;

import com.springcoresecurity.domain.dto.UserDto;
import com.springcoresecurity.domain.entity.Account;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    @GetMapping("/users")
    public String createUser() {
        return "/user/login/register";
    }

    @PostMapping("/users")
    public String createUser(UserDto userDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(userDto, Account.class);

        return "redirect:/";
    }

}
