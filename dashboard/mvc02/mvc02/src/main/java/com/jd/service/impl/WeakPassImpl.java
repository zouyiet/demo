package com.jd.service.impl;

import com.jd.dao.WeakPassDao;
import com.jd.entity.WeakPass;
import com.jd.service.WeakPassService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class WeakPassImpl implements WeakPassService {

    @Autowired
    private WeakPassDao weakPassDao;

    @Override
    public WeakPass getId(Long id) {
        return weakPassDao.getId(id);
    }

    @Override
    public List<WeakPass> getList(int start, int pageNum) {
        return weakPassDao.queryAll(start,pageNum);
    }

}
