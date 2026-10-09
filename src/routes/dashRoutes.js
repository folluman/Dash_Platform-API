const express = require('express')
const router = express.Router()
const dashboardController = require('../controllers/dashController')

const { verifyToken } = require('../middlewares/authMiddleware')
const { isAdmin } = require('../middlewares/adminMiddleware')
const { requirePasswordChanged } = require('../middlewares/passwordMiddleware')

router.post('/create', verifyToken, requirePasswordChanged, isAdmin, dashboardController.dash_create_post)

router.get('/list', verifyToken, requirePasswordChanged, dashboardController.dash_list)

router.get('/:id', verifyToken, requirePasswordChanged, dashboardController.dash_content)

router.delete('/delete/:id', verifyToken, requirePasswordChanged, isAdmin, dashboardController.dash_delete)

router.put('/update/:id', verifyToken, requirePasswordChanged, isAdmin, dashboardController.dash_update)

module.exports = router;
