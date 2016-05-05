defmodule Rumbl.Auth do
  import Plug.Conn
  import Phoenix.Controller
  alias Rumble.Router.Helpers

  def init(opts) do
    Keyword.fetch!(opts, :repo)
  end

  def call(conn, repo) do
    user_id = get_session(conn, :user_id)
    user    = user_id && repo.get(Rumbl.User, user_id)
    assign(conn, :current_user, user)
  end

  #not part of plug spec, used in controller
  def login(conn, user) do
    conn
    |> assign(:current_user, user)
    |> put_session(:user_id, user.id)
    |> configure_session(renew: true)
  end

  def login_by_username_and_pass(conn, user, given_pass, opts) do
    repo = Keyword.fetch!(opts, :repo)
    user = repo.get_by(Rumbl.User, username: user)

    cond do
      user && Comeonin.Bcrypt.checkpw(given_pass, user.password_hash) ->
        {:ok, login(conn,user)}
      user ->
        {:error, :unauthorized, conn}
      true ->
        Comeonin.Bcrypt.dummy_checkpw()
        {:error, :not_found, conn}
    end
  end

  def logout(conn) do
    configure_session(conn, drop: true)
    # or delete_session(conn, :user_id)
  end

  #plug shared with router and controllers
  def authenticate_user(conn, _opts) do
    if conn.assigns.current_user do
      conn
    else
      conn
      |> put_flash(:error, "Must be logged in")
      |> redirect(to: Helpers.page_path(conn, :index))
      |> halt()
    end
  end
end
