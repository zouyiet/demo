package com.jd.service;

import com.jd.entity.WeakPass;

import java.util.List;

public interface WeakPassService {

    WeakPass getId(Long id);

    List<WeakPass> getList(int start, int pageNum);

}
