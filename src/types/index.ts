export interface JWTHeader {
  alg: string;
  typ: string;
}

export interface JWTPayload {
  sub: string;
  username: string;
  iat: number;
  exp: number;
}

export interface AuthResponse {
  token: string;
  user: {
    id: string;
    username: string;
  };
}

export interface AuthError {
  message: string;
  status: number;
}

export interface Bookmark {
  id: string;
  title: string;
  url: string;
  tags: string[];
  createdAt: string;
}

export interface BookmarkApiResponse {
  bookmarks: Bookmark[];
  total: number;
}
