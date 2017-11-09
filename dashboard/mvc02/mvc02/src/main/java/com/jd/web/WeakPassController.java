package com.jd.web;


import com.jd.entity.WeakPass;
import com.jd.service.WeakPassService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.List;

@Controller
@RequestMapping(value = "/")
public class WeakPassController {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private WeakPassService weakpassservice;

    @RequestMapping(value = "/list", method = RequestMethod.GET)
    private String list(Model model) {
        List<WeakPass> list = weakpassservice.getList(0, 1000);
        model.addAttribute("list", list);
        System.out.println(list);
        return "list";
    }

}
