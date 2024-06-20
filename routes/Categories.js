const express = require('express');
const { fetchCategories, createCategories } = require('../controller/Category');

const router = express.Router();

router.get('/', fetchCategories)
    .post('/', createCategories)



exports.router = router;
