from user_controls.Router import Router, DataStrategyEnum
from views.file_page import file_page
from views.direct_page import directory_page
from views.text_page import text_page

router = Router(DataStrategyEnum.QUERY)

router.routes = {
  "/": file_page,
  "/directory_page": directory_page,
  "/text_page": text_page
}
