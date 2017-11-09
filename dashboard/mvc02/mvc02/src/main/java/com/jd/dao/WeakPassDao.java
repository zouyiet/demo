package com.jd.dao;

import com.jd.entity.WeakPass;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface WeakPassDao {
    WeakPass getId(long id);

    List<WeakPass> queryAll(@Param("offset") int offset, @Param("limit") int limit);

}
